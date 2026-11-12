"""Opt-in Windows-only test: disposable .invalid vault entries and local packages.

No course login, active credential, email, paid lesson or external network is used.
The vault and loopback HTTP are real; course HTTPS responses are test doubles.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import secrets
import sys
import tempfile
import queue
import threading
import subprocess
from unittest.mock import patch
import zipfile


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module


class Response(io.BytesIO):
    def __init__(self,body,url):super().__init__(body);self.address=url
    def getcode(self):return 200
    def geturl(self):return self.address


def run(runtime,entry_root=None):
    stores=load('windows_native_smoke_store',runtime/'credential_store.py')
    client=load('windows_native_smoke_updater',runtime/'update_client.py')
    api=client.api_transport()
    native=stores._NativeWindowsCredentialManager()
    vault=stores.WindowsCredentialStore(approved=True,bridge=native)
    origin='https://'+secrets.token_hex(12)+'.windows-smoke.example.invalid'
    service='com.chiluco.figma-skill|'+origin;account='figma-kanpu-totonoe'
    credential='TEST_ONLY_'+secrets.token_hex(32)
    pending={'schema':1,'origin':origin,'code':secrets.token_hex(32)+'.'+secrets.token_hex(32),'verifier':secrets.token_hex(32)}
    checks={};state={'version':1};network_calls=[];packages={}
    def package():
        if state['version'] in packages:return packages[state['version']]
        files={p.name:p.read_bytes() for p in runtime.glob('*.py')}
        body={'scripts/'+name:data for name,data in files.items()}
        # Satisfy the package format without publishing or exercising paid lessons.
        body['scripts/verify_layout_rules.py']=b'"""Disposable fixture; no design validation is performed here."""\n'
        body['references/練習用_カンプ.md']='有料教材ではない日本語の試験データ\n'.encode('utf-8')
        body['SKILL.md']=('---\nname: figma-kanpu-totonoe\ndescription: Disposable test only\n---\n\nTest content '+str(state['version'])+'\n').encode()
        release={'schema':1,'bootstrap_version':2,'name':client.NAME,'version':'0.0.'+str(state['version'])+'-trial.1',
                 'requirements':['figma-mcp','image-generation'],'authenticated_delivery_protocol':1,'credential_storage_protocol':1,
                 'files':{name:hashlib.sha256(data).hexdigest() for name,data in body.items()}}
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('release.json',json.dumps(release))
            for name,data in body.items():z.writestr('skills/'+client.NAME+'/'+name,data)
        data=stream.getvalue()
        packages[state['version']]=({'schema':1,'release':release,'package_bytes':len(data),'package_sha256':hashlib.sha256(data).hexdigest()},data)
        return packages[state['version']]
    def local_https(request,timeout):
        assert request.get_header('Authorization')=='Bearer '+credential
        prefix=origin+'/wp-json/chika-skill-self/v1/'
        assert request.full_url in (prefix+'manifest',prefix+'package')
        manifest,data=package();network_calls.append(request.full_url.rsplit('/',1)[-1])
        return Response(json.dumps(manifest).encode() if request.full_url.endswith('/manifest') else data,request.full_url)
    result={'status':'FAIL','platform':sys.platform,'real_windows_vault':True,'course_network':'local response double; no external HTTP','browser_network':'real loopback HTTP','checks':checks}
    try:
        browser=load('windows_native_smoke_browser',(entry_root or runtime.parent)/'browser_input.py')
        ready=queue.Queue();entered=[];entry_errors=[]
        def read_browser():
            try:entered.append(browser.read_code(timeout=45,announce=ready.put))
            except Exception:entry_errors.append(True);ready.put(None)
        worker=threading.Thread(target=read_browser,daemon=True);worker.start();url=ready.get(timeout=5)
        assert isinstance(url,str) and url.startswith('http://127.0.0.1:')
        dummy_code='a'*64+'.'+'b'*64
        chrome_test=Path(__file__).with_name('windows_browser_smoke.cjs')
        completed=subprocess.run(['node',str(chrome_test),url],capture_output=True,text=True,timeout=45,check=True)
        assert json.loads(completed.stdout)=={'status':'PASS','real_chrome_form_submit':True}
        worker.join(timeout=3);assert not worker.is_alive() and entered==[dummy_code] and not entry_errors
        checks['real_chrome_form_submit']=True
        checks['local_browser_password_input']=True
        assert vault.read(origin) is None and vault.pending_read(origin) is None
        vault.put(origin,credential);assert vault.read(origin)==credential
        checks['native_store_readback']=True
        try:vault.put(origin,credential+'different')
        except stores.StoreError:pass
        else:raise AssertionError('existing entry overwritten')
        assert vault.read(origin)==credential;checks['existing_credential_preserved']=True
        vault.pending_put(origin,pending);assert vault.pending_read(origin)==pending
        try:vault.pending_clear(origin,'0'*64)
        except stores.StoreError:pass
        else:raise AssertionError('wrong pending tag accepted')
        vault.pending_clear(origin,stores.pending_tag(pending));assert vault.pending_read(origin) is None
        checks['pending_roundtrip_and_scoped_clear']=True
        with tempfile.TemporaryDirectory(prefix='course-windows-smoke-') as temporary:
            root=Path(temporary)/'受講者の練習環境'/client.NAME;state_dir=root.parent/('.'+client.NAME+'-updater')
            with patch.object(api.urllib.request,'build_opener') as opener:
                opener.return_value.open=local_https
                installed=api.install(origin,root,True,client,endpoint_profile='wordpress_self_registration_v1',credential_backend='windows_credential_manager')
                result['last_operation']='install'
                result['last_operation_status']=installed['status']
                assert installed['status']=='installed';before=client.hashes(root)
                checks['install_with_saved_windows_credential']=True
                assert client.update(root,state_dir)['status']=='current'
                state['version']=2;updated=client.update(root,state_dir)
                result['last_operation']='update'
                result['last_operation_status']=updated['status']
                assert updated['status']=='updated' and client.hashes(root)!=before
                assert client.update(root,state_dir)['status']=='current'
                checks['changed_content_update_and_current']=True
                config=json.loads((state_dir/'config.json').read_text(encoding='utf-8'))
                assert config['source']==origin and config['credential_backend']=='windows_credential_manager'
                restored=client.local_transport().restore(root,state_dir,client)
                result['last_operation']='restore'
                result['last_operation_status']=restored['status']
                assert restored['status']=='restored' and client.hashes(root)==before
                checks['previous_content_restored']=True
                assert credential not in json.dumps(config)
                checks['config_contains_no_secret']=True
        result['status']='PASS';result['local_manifest_package_requests']=len(network_calls)
    except Exception as exc:
        # No exception message/trace: it may contain a native object or secret.
        result['error_type']=type(exc).__name__
    finally:
        try:
            if vault.pending_read(origin) is not None:vault.pending_clear(origin,stores.pending_tag(pending))
            target=native.target(service,account)
            # This is the one disposable test item, never a real course credential.
            assert origin.endswith('.windows-smoke.example.invalid')
            with native.locked(target):
                saved=native._read(target)
                if saved is not None:
                    assert saved==credential
                    assert native.api.CredDeleteW(target,1,0)
                assert native._read(target) is None
            checks['disposable_items_removed']=True
        except Exception:
            result['status']='FAIL';checks['disposable_items_removed']=False
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--accept-disposable-vault-test',action='store_true')
    args=parser.parse_args()
    if sys.platform!='win32' or not args.accept_disposable_vault_test:
        print(json.dumps({'status':'NOT_RUN','reason':'Windows and explicit disposable-vault-test flag required'}));return 2
    result=run(Path(__file__).parent/'runtime')
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
