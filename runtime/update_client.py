#!/usr/bin/env python3
"""Noninteractive validated skill-only update from the approved source.

Authenticated delivery reads its dedicated credential from the configured OS
store. Git compatibility mode uses existing Git access. Configuration/state live
outside the replaceable skill directory; neither mode accepts secret arguments.
"""
import argparse
import ast
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile
from urllib.parse import urlsplit

NAME = 'figma-kanpu-totonoe'
MAX_BYTES = 10 * 1024 * 1024


def hashes(folder):
    result = {}
    if not folder.is_dir():
        return result
    for p in sorted(folder.rglob('*')):
        if '__pycache__' in p.parts or p.name == '.DS_Store':
            continue
        if p.is_symlink():
            raise ValueError('symlink_in_skill')
        if p.is_file():
            result[p.relative_to(folder).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.state-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def git(cache, *args):
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GCM_INTERACTIVE='Never')
    process = subprocess.run(['git', '-C', str(cache), *args], env=env,
                             capture_output=True, timeout=25)
    if process.returncode:
        # Git stderr can include transport details. Never echo it or credentials.
        raise ValueError('source_unavailable')
    return process.stdout


def check_source(source, test_fixture=False):
    parsed = urlsplit(source)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('source_credentials_or_parameters_not_allowed')
    if test_fixture and parsed.scheme == 'file' and parsed.netloc in ('', 'localhost'):
        return
    if parsed.scheme != 'https' or parsed.hostname != 'github.com':
        raise ValueError('source_must_be_github_https')
    if not re.fullmatch(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?', parsed.path):
        raise ValueError('invalid_repository_path')


def validate_release(cache, commit, config):
    release = json.loads(git(cache, 'show', commit + ':release.json'))
    if release.get('schema') != 1 or release.get('name') != NAME:
        raise ValueError('unsupported_release')
    if release.get('bootstrap_version') != config.get('approved_bootstrap_version', 1):
        raise ValueError('bootstrap_change_requires_setup')
    if not isinstance(release.get('version'), str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', release['version']):
        raise ValueError('invalid_version')
    if set(release.get('requirements', [])) != set(config['approved_requirements']):
        raise ValueError('new_requirements_need_initial_setup_review')
    prefix = 'skills/' + NAME + '/'
    entries = git(cache, 'ls-tree', '-r', commit, '--', prefix).decode().splitlines()
    if not entries or len(entries) > 200:
        raise ValueError('invalid_file_inventory')
    for entry in entries:
        mode, rest = entry.split(' ', 1)
        if mode not in ('100644', '100755') or '\t' not in rest:
            raise ValueError('unsupported_file_type')
    payload = git(cache, 'archive', '--format=zip', commit, prefix)
    if len(payload) > MAX_BYTES:
        raise ValueError('release_too_large')
    extracted = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or '..' in path.parts or not entry.filename.startswith(prefix):
                raise ValueError('unsafe_archive_path')
            relative = entry.filename[len(prefix):]
            if relative in extracted or not relative or '\\' in relative:
                raise ValueError('invalid_archive_entry')
            if Path(relative).suffix.lower() not in ('.md', '.py', '.json', '.yaml', '.yml', '.png', '.jpg', '.jpeg', '.svg'):
                raise ValueError('unsupported_packaged_file')
            total += entry.file_size
            if total > MAX_BYTES:
                raise ValueError('release_too_large')
            extracted[relative] = archive.read(entry)
    measured = {p: hashlib.sha256(b).hexdigest() for p, b in extracted.items()}
    if measured != release.get('files'):
        raise ValueError('checksum_mismatch')
    skill = extracted.get('SKILL.md', b'').decode('utf-8')
    if not skill.startswith('---\n') or len(skill.split('---', 2)) != 3:
        raise ValueError('invalid_skill_identity')
    if not re.search(r'^name:\s*' + re.escape(NAME) + r'\s*$', skill.split('---', 2)[1], re.M):
        raise ValueError('invalid_skill_identity')
    if 'description:' not in skill.split('---', 2)[1]:
        raise ValueError('missing_skill_description')
    for path, data in extracted.items():
        if path.endswith('.py'):
            ast.parse(data.decode('utf-8'), filename=path)
    return release, extracted


def recover(root, state_dir, state):
    journal = state_dir / 'pending.json'
    if not journal.exists():
        return state
    pending = json.loads(journal.read_text(encoding='utf-8'))
    if not isinstance(pending, dict) or not isinstance(pending.get('new_state'), dict) or not isinstance(pending['new_state'].get('installed_hashes'), dict):
        raise ValueError('invalid_recovery_record')
    backup = Path(pending['backup'])
    if backup.parent != root.parent or not backup.name.startswith('.' + NAME + '-backup-'):
        raise ValueError('invalid_recovery_record')
    current = hashes(root)
    if current == pending['new_state']['installed_hashes']:
        state = pending['new_state']
        write_json(state_dir / 'state.json', state)
    elif not root.exists() and backup.exists():
        os.replace(backup, root)
    elif current != state['installed_hashes']:
        raise ValueError('recovery_needs_review')
    journal.unlink()
    return state



def version_key(value):
    """Order supported versions, including prerelease numeric identifiers."""
    core, separator, prerelease = value.partition('-')
    numbers = tuple(int(part) for part in core.split('.'))
    if not separator:
        return numbers, 1, ()
    identifiers = tuple((0, int(part)) if part.isdigit() else (1, part)
                        for part in prerelease.split('.'))
    return numbers, 0, identifiers


def activate(root, state_dir, state, release, files, commit):
    stage = Path(tempfile.mkdtemp(dir=root.parent, prefix='.' + NAME + '-stage-'))
    backup = root.parent / ('.' + NAME + '-backup-' + uuid.uuid4().hex)
    try:
        for path, data in files.items():
            target = stage / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        if hashes(root) != state['installed_hashes']:
            return {'status': 'local_changes', 'retained_installed_version': has_skill(root)}
        new_state = {'version': release['version'], 'commit': commit,
                     'installed_hashes': release['files'], 'backup': str(backup),
                     'previous_state': {k: state[k] for k in ('version', 'commit', 'installed_hashes')}}
        write_json(state_dir / 'pending.json', {'backup': str(backup), 'new_state': new_state})
        os.replace(root, backup)
        try:
            os.replace(stage, root)
            write_json(state_dir / 'state.json', new_state)
        except BaseException:
            if root.exists():
                failed = root.parent / ('.' + NAME + '-failed-' + uuid.uuid4().hex)
                os.replace(root, failed)
            os.replace(backup, root)
            raise
        (state_dir / 'pending.json').unlink()
        return {'status': 'updated', 'version': release['version'], 'reread_skill': True}
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def has_skill(root):
    return root.is_dir() and (root / 'SKILL.md').is_file() and (root / 'scripts/update_client.py').is_file()


def update(root, state_dir, test_fixture=False):
    root, state_dir = Path(root).resolve(), Path(state_dir).resolve()
    if root == state_dir or root in state_dir.parents:
        return {'status': 'blocked', 'reason': 'state_must_be_outside_skill'}
    if not (state_dir / 'config.json').exists() or not (state_dir / 'state.json').exists():
        return {'status': 'not_configured', 'retained_installed_version': has_skill(root)}
    lock = state_dir / 'updating.lock'
    try:
        lock.mkdir()
    except FileExistsError:
        result = {'status': 'busy', 'retained_installed_version': has_skill(root)}
        try:
            saved = json.loads((state_dir / 'config.json').read_text(encoding='utf-8'))
            if saved.get('source_kind') == 'authenticated_api' and saved.get('access_blocked') is True:
                result['may_use_installed'] = False
        except (OSError, ValueError, TypeError, AttributeError):
            result['may_use_installed'] = False
        return result
    try:
        config = json.loads((state_dir / 'config.json').read_text(encoding='utf-8'))
        if not isinstance(config, dict):
            raise ValueError('invalid_config')
        if config.get('trusted_at_install') is not True:
            raise ValueError('initial_setup_not_approved')
        if config.get('updates_paused') is True:
            return {'status': 'paused', 'retained_installed_version': has_skill(root), 'may_use_installed': not (config.get('source_kind') == 'authenticated_api' and config.get('access_blocked') is True)}
        if config.get('source_kind') == 'authenticated_api':
            return api_transport().update(root, state_dir, config, api_client_facade())
        if config.get('source_kind') == 'local_zip':
            state = recover(root, state_dir, json.loads((state_dir / 'state.json').read_text(encoding='utf-8')))
            if not isinstance(state, dict) or not isinstance(state.get('installed_hashes'), dict):
                raise ValueError('invalid_state')
            if hashes(root) != state['installed_hashes']:
                return {'status': 'local_changes', 'retained_installed_version': has_skill(root)}
            release, files, digest = local_transport().read_package(config['source'], config.get('approved_bootstrap_version', 1))
            if set(release['requirements']) != set(config['approved_requirements']):
                raise ValueError('requirements_changed')
            commit = 'zip:' + digest
            if commit == state.get('commit'):
                return {'status': 'current', 'version': state['version'], 'source_kind': 'local_zip'}
            if version_key(release['version']) <= version_key(state['version']):
                raise ValueError('same_version_or_downgrade')
            if hashes(root) != state['installed_hashes']:
                return {'status': 'local_changes', 'retained_installed_version': has_skill(root)}
            return activate(root, state_dir, state, release, files, commit)
        check_source(config['source'], test_fixture)
        if config.get('branch') != 'stable':
            raise ValueError('only_tested_stable_channel_allowed')
        state = recover(root, state_dir, json.loads((state_dir / 'state.json').read_text(encoding='utf-8')))
        if hashes(root) != state['installed_hashes']:
            return {'status': 'local_changes', 'retained_installed_version': has_skill(root)}
        cache = state_dir / 'git-cache'
        if not cache.exists():
            cache.mkdir()
            git(cache, 'init', '--bare')
        git(cache, 'fetch', '--no-tags', '--depth=1', config['source'], 'refs/heads/stable')
        commit = git(cache, 'rev-parse', 'FETCH_HEAD').decode().strip()
        if commit == state.get('commit'):
            return {'status': 'current', 'version': state['version']}
        # Only advance on the same stable history. Initial installs also pin a SHA.
        old_commit = state.get('commit')
        if old_commit:
            git(cache, 'fetch', '--no-tags', config['source'], old_commit)
            try:
                git(cache, 'merge-base', '--is-ancestor', old_commit, commit)
            except ValueError:
                # A shallow tip may lack parents; fetch stable history before judging.
                git(cache, 'fetch', '--no-tags', '--unshallow', config['source'], 'refs/heads/stable')
                git(cache, 'merge-base', '--is-ancestor', old_commit, commit)
        release, files = validate_release(cache, commit, config)
        if release['version'] == state['version']:
            raise ValueError('changed_release_must_bump_version')
        if version_key(release['version']) <= version_key(state['version']):
            raise ValueError('version_downgrade_not_allowed')
        # Last check immediately before activation, in case the learner edited meanwhile.
        if hashes(root) != state['installed_hashes']:
            return {'status': 'local_changes', 'retained_installed_version': has_skill(root)}
        return activate(root, state_dir, state, release, files, commit)
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError, SyntaxError, zipfile.BadZipFile):
        result = {'status': 'kept_previous', 'reason': 'update_not_applied', 'retained_installed_version': has_skill(root)}
        if isinstance(locals().get('config'), dict) and config.get('source_kind') == 'authenticated_api':
            result['may_use_installed'] = False
        return result
    finally:
        lock.rmdir()


def api_client_facade():
    import types
    return types.SimpleNamespace(**{k: globals()[k] for k in ['NAME','recover','hashes','has_skill','write_json','version_key','activate','local_transport']})


def api_transport():
    spec = importlib.util.spec_from_file_location('chika_authenticated_delivery', Path(__file__).with_name('authenticated_delivery.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def local_transport():
    spec = importlib.util.spec_from_file_location('chika_zip_package', Path(__file__).with_name('zip_package.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--skill-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--restore', action='store_true', help='Restore verified previous version and pause updates')
    parser.add_argument('--test-fixture', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    state_dir = args.state_dir or args.skill_root.parent / ('.' + NAME + '-updater')
    result = local_transport().restore(args.skill_root, state_dir, __import__(__name__)) if args.restore else update(args.skill_root, state_dir, args.test_fixture)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
