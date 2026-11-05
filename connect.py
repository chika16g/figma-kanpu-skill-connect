"""Approved initial setup/resume. No OS access unless explicitly selected; no secrets in argv."""
import argparse,getpass,importlib.util,json,sys
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).parent/'runtime'/(name+'.py'));m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
class SafeParser(argparse.ArgumentParser):
    def error(self,message):raise ValueError('invalid_arguments')
def main():
    p=SafeParser();p.add_argument('--origin',required=True);p.add_argument('--destination',type=Path,required=True);p.add_argument('--accept-source',action='store_true');p.add_argument('--endpoint-profile',choices=['standalone_v1','wordpress_rest_v1','wordpress_self_registration_v1'],default='standalone_v1');p.add_argument('--use-macos-keychain',action='store_true')
    g=p.add_mutually_exclusive_group();g.add_argument('--pair',action='store_true');g.add_argument('--resume',action='store_true');g.add_argument('--install-only',action='store_true');p.add_argument('--restart-pairing',action='store_true')
    a=p.parse_args();client=load('update_client');api=load('authenticated_delivery');store=None
    if not a.accept_source:return {'status':'setup_required','reason':'review_source_at_initial_install'}
    api.origin_url(a.origin);raw=Path(a.destination);root=raw.resolve();state=root.parent/('.'+client.NAME+'-updater')
    if raw.is_symlink() or root.exists() or state.exists() or state.is_symlink():return {'status':'not_installed','reason':'existing_installation_preserved'}
    if a.restart_pairing and not a.pair:return {'status':'restart_requires_pair'}
    if a.pair and not sys.stdin.isatty():return {'status':'secure_input_required'}
    if a.use_macos_keychain:store=load('credential_store').MacOSKeychainStore(approved=True)
    if (a.pair or a.resume or a.install_only) and (store is None or a.endpoint_profile!='wordpress_self_registration_v1'):return {'status':'secure_store_setup_required'}
    if store is not None:api.configure_credential_store(store)
    pair=load('pair_client') if store is not None else None
    def install():return api.install(a.origin,a.destination,True,client,endpoint_profile=a.endpoint_profile,credential_backend='macos_keychain' if store is not None else None)
    def finished(result):
        if result.get('status')=='installed' and store is not None and not pair.clear_pending_after_install(a.origin,store):result['pending_cleanup']='not_completed_credential_preserved'
        return result
    if a.resume or a.install_only:
        # A prior ACK may have succeeded even if its response was lost. Verify by actual install.
        r=install()
        if r['status']=='installed' or a.install_only:return finished(r)
        if r['status'] not in ('access_denied','credential_setup_required'):return dict(r,next_action='retry_same_resume_or_install_only')
    if a.pair:
        if a.restart_pairing:
            if getpass.getpass('未完了の接続記録だけを消す場合は RESTART と入力: ')!='RESTART':return {'status':'restart_not_confirmed'}
            if not pair.clear_pending_record(a.origin,store):return {'status':'pending_record_preserved'}
        code=getpass.getpass('初回接続コード: ');r=pair.exchange(a.origin,code,store,api)
        if r['status']!='paired':return r
    elif a.resume:
        r=pair.exchange(a.origin,None,store,api)
        if r['status']!='paired':return r
    return finished(install())
if __name__=='__main__':
    try:r=main()
    except Exception:r={'status':'setup_not_completed'}
    print(json.dumps(r,ensure_ascii=False));raise SystemExit(0 if r['status']=='installed' else 1)
