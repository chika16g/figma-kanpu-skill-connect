"""Local package transport. Never extracts arbitrary ZIP paths or accesses a network."""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import unicodedata
import zipfile

NAME = 'figma-kanpu-totonoe'
MAX_BYTES = 10 * 1024 * 1024
REQUIRED = {'SKILL.md', 'scripts/update_client.py', 'scripts/verify_layout_rules.py'}
REQUIREMENTS = ['figma-mcp', 'image-generation']


def read_package(path, approved_bootstrap=None):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError('invalid_local_package')
    # One bounded immutable read prevents changes between validation and activation.
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise ValueError('release_too_large')
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if not infos or len(infos) > 600:
            raise ValueError('invalid_file_inventory')
        seen = set(); entries = {}; total = 0
        for item in infos:
            raw = item.filename
            if raw != item.orig_filename or '\\' in raw or '\x00' in raw:
                raise ValueError('unsafe_archive_path')
            parts = raw.rstrip('/').split('/')
            if not parts or raw.startswith('/') or any(p in ('', '.', '..') or ':' in p or p.rstrip(' .') != p for p in parts):
                raise ValueError('unsafe_archive_path')
            # Case/NFC aliases are unsafe on common learner filesystems.
            key = unicodedata.normalize('NFC', raw.rstrip('/')).casefold()
            if key in seen:
                raise ValueError('duplicate_archive_entry')
            seen.add(key)
            mode = stat.S_IFMT(item.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or item.flag_bits & 1:
                raise ValueError('unsupported_file_type')
            if item.is_dir():
                if mode == stat.S_IFREG:
                    raise ValueError('invalid_directory')
                continue
            if mode == stat.S_IFDIR:
                raise ValueError('invalid_file')
            total += item.file_size
            if total > MAX_BYTES:
                raise ValueError('release_too_large')
            entries[raw] = z.read(item)
    manifests = [p for p in entries if p == 'release.json' or (p.count('/') == 1 and p.endswith('/release.json'))]
    if len(manifests) != 1:
        raise ValueError('missing_or_ambiguous_manifest')
    manifest_path = manifests[0]; prefix = manifest_path[:-len('release.json')]
    if prefix and not prefix.startswith(NAME + '-'):
        raise ValueError('invalid_package_root')
    if prefix and any(not p.startswith(prefix) for p in entries):
        raise ValueError('mixed_package_roots')
    release = json.loads(entries[manifest_path])
    if not isinstance(release, dict) or release.get('schema') != 1 or release.get('name') != NAME:
        raise ValueError('unsupported_release')
    bootstrap = release.get('bootstrap_version')
    if bootstrap not in (1, 2) or (approved_bootstrap is not None and bootstrap != approved_bootstrap):
        raise ValueError('bootstrap_change_requires_setup')
    if not isinstance(release.get('version'), str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', release['version']):
        raise ValueError('invalid_version')
    requirements = release.get('requirements')
    if not isinstance(requirements, list) or sorted(requirements) != sorted(REQUIREMENTS):
        raise ValueError('new_requirements_need_setup')
    payload_prefix = prefix + 'skills/' + NAME + '/'
    files = {p[len(payload_prefix):]: b for p, b in entries.items() if p.startswith(payload_prefix)}
    if not REQUIRED.issubset(files) or not files or len(files) > 200:
        raise ValueError('missing_skill_body')
    measured = {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}
    if measured != release.get('files'):
        raise ValueError('checksum_mismatch')
    for p, b in files.items():
        if Path(p).suffix.lower() not in ('.md', '.py', '.json', '.yaml', '.yml', '.png', '.jpg', '.jpeg', '.svg'):
            raise ValueError('unsupported_packaged_file')
        if p.endswith('.py'):
            ast.parse(b.decode('utf-8'), filename=p)
    skill = files['SKILL.md'].decode('utf-8')
    if not skill.startswith('---\n') or len(skill.split('---', 2)) != 3:
        raise ValueError('invalid_skill_identity')
    front = skill.split('---', 2)[1]
    if not re.search(r'^name:\s*' + NAME + r'\s*$', front, re.M) or not re.search(r'^description:\s*\S', front, re.M):
        raise ValueError('invalid_skill_identity')
    if bootstrap == 2 and 'scripts/zip_package.py' not in files:
        raise ValueError('missing_local_transport')
    return release, files, hashlib.sha256(data).hexdigest()


def install_zip(path, destination, accept_source, client, initial_config=None, initial_commit=None):
    if not accept_source:
        return {'status': 'setup_required', 'reason': 'review_source_at_initial_install'}
    raw_destination = Path(destination)
    if raw_destination.is_symlink():
        return {'status': 'not_installed', 'reason': 'existing_installation_preserved'}
    root = raw_destination.resolve(); state_dir = root.parent / ('.' + NAME + '-updater')
    if root.exists() or state_dir.exists() or state_dir.is_symlink():
        return {'status': 'not_installed', 'reason': 'existing_installation_preserved'}
    reserved_inode = None; state_owned = False; stage = None
    try:
        release, files, digest = read_package(path)
        if release['bootstrap_version'] != 2:
            raise ValueError('local_mode_requires_bootstrap_2')
        if initial_config is not None:
            if not isinstance(initial_config, dict) or initial_config.get('source_kind') != 'authenticated_api' or initial_config.get('trusted_at_install') is not True or initial_config.get('approved_bootstrap_version') != release['bootstrap_version'] or sorted(initial_config.get('approved_requirements', [])) != sorted(REQUIREMENTS) or not isinstance(initial_commit, str) or not initial_commit.startswith('api:'):
                raise ValueError('invalid_initial_api_config')
        root.parent.mkdir(parents=True, exist_ok=True)
        state_dir.mkdir(); state_owned = True
        root.mkdir(); reserved_inode = root.stat().st_ino
        stage = Path(tempfile.mkdtemp(dir=root.parent, prefix='.chika-zip-install-'))
        for name, data in files.items():
            target = stage / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        client.write_json(state_dir / 'config.json', initial_config or {'source_kind': 'local_zip', 'source': str(Path(path).resolve()),
            'trusted_at_install': True, 'approved_requirements': REQUIREMENTS,
            'approved_bootstrap_version': release['bootstrap_version']})
        client.write_json(state_dir / 'state.json', {'version': release['version'], 'commit': initial_commit or 'zip:' + digest, 'installed_hashes': release['files']})
        if root.is_symlink() or root.stat().st_ino != reserved_inode or any(root.iterdir()):
            raise ValueError('destination_changed_concurrently')
        os.replace(stage, root)
        return {'status': 'installed', 'version': release['version'], 'source_kind': 'local_zip',
                'automatic_check': 'approved_local_zip_on_skill_start', 'network': False}
    except (OSError, ValueError, TypeError, KeyError, SyntaxError, zipfile.BadZipFile, UnicodeError):
        if reserved_inode is not None and root.is_dir() and not root.is_symlink() and root.stat().st_ino == reserved_inode and not any(root.iterdir()):
            root.rmdir()
        if state_owned:
            shutil.rmtree(state_dir)
        return {'status': 'not_installed', 'reason': 'local_package_unavailable_or_invalid'}
    finally:
        if stage and stage.exists():
            shutil.rmtree(stage)


def restore(root, state_dir, client):
    root = Path(root).resolve(); state_dir = Path(state_dir).resolve()
    if root == state_dir or root in state_dir.parents:
        return {'status': 'blocked', 'reason': 'state_must_be_outside_skill'}
    lock = state_dir / 'updating.lock'
    try:
        lock.mkdir()
    except (FileExistsError, FileNotFoundError):
        return {'status': 'restore_not_applied', 'reason': 'busy_or_not_configured'}
    previous = None; failed = None
    try:
        config = json.loads((state_dir / 'config.json').read_text()); state = json.loads((state_dir / 'state.json').read_text())
        if not isinstance(config, dict) or not isinstance(state, dict) or (state_dir / 'pending.json').exists():
            raise ValueError('restore_needs_review')
        if client.hashes(root) != state['installed_hashes']:
            raise ValueError('local_changes')
        previous = state['previous_state']; backup = Path(state['backup'])
        if backup.parent != root.parent or not backup.name.startswith('.' + NAME + '-backup-') or backup.is_symlink():
            raise ValueError('invalid_backup')
        if client.hashes(backup) != previous['installed_hashes']:
            raise ValueError('backup_mismatch')
        # Pause first; errors or a second startup cannot silently reinstall the rejected candidate.
        config['updates_paused'] = True; client.write_json(state_dir / 'config.json', config)
        import uuid
        failed = root.parent / ('.' + NAME + '-restored-from-' + uuid.uuid4().hex)
        client.write_json(state_dir / 'pending.json', {'backup': str(backup), 'new_state': previous})
        os.replace(root, failed)
        try:
            os.replace(backup, root)
            client.write_json(state_dir / 'state.json', previous)
        except BaseException:
            if root.exists():
                os.replace(root, backup)
            os.replace(failed, root)
            raise
        (state_dir / 'pending.json').unlink()
        return {'status': 'restored', 'version': previous['version'], 'updates_paused': True, 'retained_newer_copy': str(failed)}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'restore_not_applied', 'reason': 'restore_needs_review', 'retained_installed_version': root.is_dir()}
    finally:
        lock.rmdir()
