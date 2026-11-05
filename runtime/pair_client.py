"""Resumable initial pairing. Recovery data stays in an explicitly selected secure store."""
import hashlib,hmac,json,secrets,urllib.request,urllib.error,re

def exchange(origin,code,store,api,*,opener=None,verifier=None):
    if store is None:return {'status':'secure_store_setup_required'}
    if not all(callable(getattr(store,n,None)) for n in ('read','put','pending_read','pending_put','pending_clear')):return {'status':'recovery_store_setup_required'}
    try:
        origin=api.origin_url(origin);old=store.pending_read(origin);resuming=old is not None
        if code is None:
            if old is None:return {'status':'no_pending_pairing'}
            code=old['code']
        if not isinstance(code,str) or not re.fullmatch(r'[a-f0-9]{64}\.[a-f0-9]{64}',code):return {'status':'new_pairing_code_required'}
        if old is not None:
            if old['code']!=code or verifier is not None and old['verifier']!=verifier:return {'status':'pending_pairing_preserved_use_resume_or_restart'}
            verifier=old['verifier']
        else:
            verifier=verifier if verifier is not None else secrets.token_hex(32)
            if not isinstance(verifier,str) or not re.fullmatch(r'[a-f0-9]{64}',verifier):raise ValueError('verifier')
            store.pending_put(origin,{'schema':1,'origin':origin,'code':code,'verifier':verifier})
        pid=code.split('.')[1];prefix=api.endpoint_prefix('wordpress_self_registration_v1')
        send=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),api.NoRedirect()).open
        def post(route,body):
            url=origin+prefix+'pair/'+route;req=urllib.request.Request(url,data=json.dumps(body).encode(),method='POST',headers={'Content-Type':'application/json','Origin':origin,'Accept':'application/json'})
            with send(req,timeout=15) as response:
                if response.getcode()!=200 or response.geturl()!=url:raise ValueError('request_rejected')
                b=response.read(8193)
                if len(b)>8192:raise ValueError('response_too_large')
                return json.loads(b)
        request={'code':code,'verifier':verifier}
        def ack(secret):
            data=dict(request,ack=hmac.new(secret.encode(),('stored|'+pid+'|'+verifier).encode(),hashlib.sha256).hexdigest())
            for attempt in range(2):
                try:
                    r=post('ack',data)
                    return {'status':'paired','qualification_basis':'page_entry_only','individual_purchase_verified':False} if isinstance(r,dict) and r.get('status')=='registered' else {'status':'pairing_ack_pending','credential_retained_in_secure_store':True}
                except urllib.error.HTTPError as e:
                    if e.code in (403,409):return {'status':'pairing_restart_required'}
                    if attempt==1:return {'status':'pairing_ack_pending','credential_retained_in_secure_store':True}
                except (OSError,ValueError,urllib.error.URLError):
                    if attempt==1:return {'status':'pairing_ack_pending','credential_retained_in_secure_store':True}
        if resuming:
            saved=store.read(origin)
            if saved is not None:return ack(saved)
        r=None
        for attempt in range(2):
            try:r=post('claim',request);break
            except urllib.error.HTTPError as e:return {'status':'pairing_restart_required'} if e.code in (403,409) else {'status':'pairing_not_completed'}
            except (OSError,ValueError,urllib.error.URLError):
                if attempt==1:raise
        if not isinstance(r,dict) or set(r)!={'status','credential','pair_id'} or r['status']!='store_required' or r['pair_id']!=pid:raise ValueError('claim_rejected')
        secret=r['credential']
        if not isinstance(secret,str) or not 32<=len(secret)<=4096 or any(not 33<=ord(c)<=126 for c in secret):raise ValueError('invalid_credential')
        try:
            store.put(origin,secret)
            if store.read(origin)!=secret:raise ValueError('store_verification_failed')
        except Exception:
            try:post('abort',request)
            except Exception:pass
            return {'status':'secure_store_failed','existing_credentials_preserved':True}
        return ack(secret)
    except Exception:return {'status':'pairing_not_completed'}

def clear_pending_record(origin,store):
    try:
        value=store.pending_read(origin)
        if value is not None:
            # The store checks the current version atomically (native generic attribute tag).
            text=json.dumps(value,sort_keys=True,separators=(',',':'));store.pending_clear(origin,hashlib.sha256(text.encode()).hexdigest())
        return True
    except Exception:return False

def clear_pending_after_install(origin,store):
    return clear_pending_record(origin,store)
