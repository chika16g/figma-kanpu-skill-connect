"""Independent authenticated-delivery transport; never handles a real credential by default.

The production credential/purchase adapters are intentionally not connected.
Tests inject fixed TEST_ONLY credentials and an in-process HTTP transport.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import zipfile
import urllib.error
import urllib.parse
import urllib.request


MAX_BYTES = 10 * 1024 * 1024
AUTHENTICATED_DELIVERY_PROTOCOL = 1
ENDPOINT_PROFILES = {
    "standalone_v1": "/v1/",
    "wordpress_rest_v1": "/wp-json/chika-skill/v1/",
    "wordpress_self_registration_v1": "/wp-json/chika-skill-self/v1/",
}


def endpoint_prefix(profile):
    if not isinstance(profile, str) or profile not in ENDPOINT_PROFILES:
        raise ValueError("unknown_endpoint_profile")
    return ENDPOINT_PROFILES[profile]


def validate_capability(release, files):
    # A legacy Git/ZIP payload cannot update an authenticated_api installation.
    if (type(release.get("authenticated_delivery_protocol")) is not int
            or release["authenticated_delivery_protocol"] != AUTHENTICATED_DELIVERY_PROTOCOL
            or "scripts/authenticated_delivery.py" not in files):
        raise ValueError("authenticated_delivery_capability_required")


class AccessDenied(ValueError):
    pass


class CredentialRequired(AccessDenied):
    pass


_credential_store = None

def configure_credential_store(store):
    """Explicit host/session injection only; caller owns approval and lifetime."""
    global _credential_store
    _credential_store = store

def load_store_module():
    import importlib.util
    import sys
    name='_chika_origin_credential_store'
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name('credential_store.py'))
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def credential_for_origin(origin):
    # Default import/access is inert. A host can inject an approved origin-scoped store.
    if _credential_store is None:return None
    return _credential_store.read(origin_url(origin))

def approved_store_for_config(config):
    if config.get('credential_backend') is None:return None
    if config.get('credential_backend')!='macos_keychain':raise ValueError('unknown_credential_backend')
    return load_store_module().MacOSKeychainStore(approved=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin_url(value):
    if not isinstance(value, str):
        raise ValueError('invalid_origin')
    p = urllib.parse.urlsplit(value)
    if (p.scheme != 'https' or not p.hostname or p.username or p.password
            or p.query or p.fragment or p.path not in ('', '/')
            or p.hostname.lower() in ('localhost', '127.0.0.1', '::1')
            or p.netloc != p.netloc.lower() or p.netloc.endswith('.')):
        raise ValueError('approved_https_origin_required')
    return value.rstrip('/')


def fetch(origin, credential, path, limit, opener=None, profile="standalone_v1"):
    if path not in ('/v1/manifest', '/v1/package'):
        raise ValueError('invalid_endpoint')
    target = endpoint_prefix(profile) + path.rsplit('/', 1)[1]
    req = urllib.request.Request(origin_url(origin) + target, headers={
        'Authorization': 'Bearer ' + credential, 'Accept': 'application/json' if path.endswith('manifest') else 'application/zip'})
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open
    try:
        with opener(req, timeout=15) as response:
            if response.getcode() in (401, 403):
                raise AccessDenied('not_authorized')
            if response.getcode() != 200 or response.geturl() != req.full_url:
                raise ValueError('unexpected_response_or_redirect')
            data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError('response_too_large')
            return data
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise AccessDenied('not_authorized') from None
        raise ValueError('delivery_unavailable') from None
    except (urllib.error.URLError, TimeoutError, OSError):
        # Do not echo remote errors/headers: they might contain private identifiers.
        raise ValueError('delivery_unavailable') from None


def obtain(config, client, provider=None, opener=None):
    origin = origin_url(config['source'])
    profile = config.get('endpoint_profile', 'standalone_v1')
    endpoint_prefix(profile)
    try:
        credential = provider(origin) if provider is not None else (approved_store_for_config(config).read(origin) if config.get("credential_backend") else credential_for_origin(origin))
    except Exception:
        raise CredentialRequired('credential_setup_required') from None
    if not isinstance(credential, str) or not 1 <= len(credential) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in credential):
        raise CredentialRequired('credential_setup_required')
    manifest = json.loads(fetch(origin, credential, '/v1/manifest', 1024 * 1024, opener, profile))
    if (not isinstance(manifest, dict) or manifest.get('schema') != 1
            or type(manifest.get('package_bytes')) is not int
            or not 0 < manifest['package_bytes'] <= MAX_BYTES
            or not isinstance(manifest.get('package_sha256'), str)
            or len(manifest['package_sha256']) != 64):
        raise ValueError('invalid_delivery_manifest')
    data = fetch(origin, credential, '/v1/package', MAX_BYTES, opener, profile)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != manifest['package_bytes'] or digest != manifest['package_sha256']:
        raise ValueError('package_checksum_mismatch')
    # Use the existing strict path/inventory/symlink/manifest/Python validation.
    with tempfile.TemporaryDirectory(prefix='chika-auth-validate-') as folder:
        path = Path(folder) / 'package.zip'; path.write_bytes(data)
        release, files, checked_digest = client.local_transport().read_package(path, config['approved_bootstrap_version'])
    validate_capability(release, files)
    if config.get('credential_backend') and (release.get('credential_storage_protocol') != 1 or type(release.get('credential_storage_protocol')) is not int or not {'scripts/credential_store.py','scripts/pair_client.py'} <= set(files)):
        raise ValueError('credential_storage_capability_required')
    if release != manifest['release'] or checked_digest != digest or set(release['requirements']) != set(config['approved_requirements']):
        raise ValueError('release_envelope_mismatch')
    return release, files, 'api:' + digest


def update(root, state_dir, config, client, provider=None, opener=None):
    state = client.recover(root, state_dir, json.loads((state_dir / 'state.json').read_text()))
    if client.hashes(root) != state['installed_hashes']:
        return {'status': 'local_changes', 'retained_installed_version': client.has_skill(root), 'may_use_installed': config.get('access_blocked') is not True}
    try:
        release, files, commit = obtain(config, client, provider, opener)
    except AccessDenied as exc:
        config['access_blocked'] = True
        client.write_json(state_dir / 'config.json', config)
        return {'status': 'credential_setup_required' if isinstance(exc, CredentialRequired) else 'access_denied',
            'retained_installed_version': client.has_skill(root), 'may_use_installed': False}
    except (ValueError, KeyError, OSError, TypeError, SyntaxError, zipfile.BadZipFile, UnicodeError):
        return {'status': 'kept_previous', 'reason': 'delivery_not_applied',
            'retained_installed_version': client.has_skill(root), 'may_use_installed': config.get('access_blocked') is not True}
    if config.get('access_blocked') is True:
        config['access_blocked'] = False; client.write_json(state_dir / 'config.json', config)
    if commit == state.get('commit'):
        return {'status': 'current', 'version': state['version'], 'source_kind': 'authenticated_api'}
    if client.version_key(release['version']) <= client.version_key(state['version']):
        raise ValueError('same_version_or_downgrade')
    return client.activate(root, state_dir, state, release, files, commit)


def install(source, destination, accept_source, client, provider=None, opener=None, endpoint_profile="standalone_v1", credential_backend=None):
    if not accept_source:
        return {'status': 'setup_required', 'reason': 'review_source_at_initial_install'}
    raw = Path(destination); root = raw.resolve(); state_dir = root.parent / ('.' + client.NAME + '-updater')
    if raw.is_symlink() or root.exists() or state_dir.exists() or state_dir.is_symlink():
        return {'status': 'not_installed', 'reason': 'existing_installation_preserved'}
    endpoint_prefix(endpoint_profile)
    if credential_backend not in (None,"macos_keychain"): raise ValueError("unknown_credential_backend")
    config = {'endpoint_profile': endpoint_profile, 'source_kind': 'authenticated_api', 'source': origin_url(source), 'trusted_at_install': True,
        'approved_bootstrap_version': 2, 'approved_requirements': ['figma-mcp', 'image-generation']}
    if credential_backend is not None: config["credential_backend"] = credential_backend
    try:
        release, files, commit = obtain(config, client, provider, opener)
    except CredentialRequired:
        return {'status': 'credential_setup_required', 'retained_installed_version': False}
    except AccessDenied:
        return {'status': 'access_denied', 'retained_installed_version': False, 'may_use_installed': False}
    except (ValueError, KeyError, OSError, TypeError, SyntaxError, zipfile.BadZipFile, UnicodeError):
        return {'status': 'not_installed', 'reason': 'delivery_unavailable_or_invalid'}
    # Reuse the existing safe initial reservation/activation. Stage is private and ephemeral.
    with tempfile.TemporaryDirectory(prefix='chika-auth-install-') as folder:
        path = Path(folder) / 'checked.zip'
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('release.json', json.dumps(release))
            for name, value in files.items(): z.writestr('skills/' + client.NAME + '/' + name, value)
        result = client.local_transport().install_zip(path, root, True, client, initial_config=config, initial_commit=commit)
    if result['status'] != 'installed':
        return result
    return {'status': 'installed', 'source_kind': 'authenticated_api', 'version': release['version'], 'automatic_check': 'on_skill_start'}
