"""Origin-scoped credential adapters. Import/defaults never access an OS store.

Native macOS implementation is UNTESTED against a real keychain. No CLI secret arguments,
keychain enumeration, cloud sync, access-group changes or silent permission grants.
"""
import hashlib
import json
import re
import ctypes
import sys
import urllib.parse

class StoreError(RuntimeError): pass

def origin_key(origin):
    if not isinstance(origin,str): raise StoreError('invalid_origin')
    p=urllib.parse.urlsplit(origin)
    if p.scheme!='https' or not p.hostname or p.username or p.password or p.path or p.query or p.fragment or p.netloc!=p.netloc.lower() or p.hostname in ('localhost','127.0.0.1','::1'):
        raise StoreError('invalid_origin')
    return origin

def valid_secret(value):
    return isinstance(value,str) and 32<=len(value)<=4096 and all(33<=ord(c)<=126 for c in value)

def pending_record(origin,value):
    if not isinstance(value,dict) or set(value)!={'schema','origin','code','verifier'} or value['schema']!=1 or type(value['schema']) is not int or value['origin']!=origin_key(origin) or not isinstance(value['code'],str) or not re.fullmatch(r'[a-f0-9]{64}\.[a-f0-9]{64}',value['code']) or not isinstance(value['verifier'],str) or not re.fullmatch(r'[a-f0-9]{64}',value['verifier']):
        raise StoreError('invalid_pending_record')
    return dict(value)

def pending_bytes(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def pending_tag(value):return hashlib.sha256(pending_bytes(value).encode()).hexdigest()

class MemoryStore:
    """Explicit mock, no filesystem/native I/O and never chosen as production fallback."""
    backend='memory_test_only'
    def __init__(self): self._items={}; self._pending={}
    def read(self,origin): return self._items.get(origin_key(origin))
    def put(self,origin,value):
        origin=origin_key(origin)
        if not valid_secret(value): raise StoreError('invalid_credential')
        if origin in self._items and self._items[origin]!=value: raise StoreError('existing_credential_preserved')
        self._items[origin]=value

    def pending_read(self,origin):
        origin=origin_key(origin);value=self._pending.get(origin)
        return pending_record(origin,value) if value is not None else None
    def pending_put(self,origin,value):
        value=pending_record(origin,value);old=self.pending_read(origin)
        if old is not None and old!=value:raise StoreError('pending_pairing_preserved')
        self._pending[origin]=value
    def pending_clear(self,origin,expected_tag):
        old=self.pending_read(origin)
        if old is None:return
        if pending_tag(old)!=expected_tag:raise StoreError('pending_pairing_changed')
        del self._pending[origin]

class MacOSKeychainStore:
    backend='macos_keychain'
    def __init__(self,*,approved=False,bridge=None):
        if approved is not True: raise StoreError('secure_store_approval_required')
        self._bridge=bridge # Lazy; no library load or keychain access until explicit read/put.
    def _native(self):
        if self._bridge is None: self._bridge=_NativeKeychain()
        return self._bridge
    def read(self,origin):
        origin=origin_key(origin)
        try:
            value=self._native().read('com.chiluco.figma-skill|'+origin,'figma-kanpu-totonoe')
            if value is not None and not valid_secret(value): raise StoreError('invalid_credential')
            return value
        except Exception: raise StoreError('secure_store_unavailable') from None
    def put(self,origin,value):
        origin=origin_key(origin)
        if not valid_secret(value): raise StoreError('invalid_credential')
        # Existing entries are never updated/deleted to make a pairing succeed.
        old=self.read(origin)
        if old==value:return
        if old is not None:raise StoreError('existing_credential_preserved')
        try:self._native().add('com.chiluco.figma-skill|'+origin,'figma-kanpu-totonoe',value)
        except Exception:raise StoreError('secure_store_write_failed') from None
        if self.read(origin)!=value:raise StoreError('secure_store_write_failed')

    def pending_read(self,origin):
        origin=origin_key(origin)
        try:
            raw=self._native().read('com.chiluco.figma-skill|'+origin,'figma-kanpu-totonoe.pending')
            return pending_record(origin,json.loads(raw)) if raw is not None else None
        except Exception:raise StoreError('secure_pending_unavailable') from None
    def pending_put(self,origin,value):
        value=pending_record(origin,value);old=self.pending_read(origin)
        if old==value:return
        if old is not None:raise StoreError('pending_pairing_preserved')
        try:self._native().add('com.chiluco.figma-skill|'+origin,'figma-kanpu-totonoe.pending',pending_bytes(value),tag=pending_tag(value))
        except Exception:raise StoreError('secure_pending_write_failed') from None
        if self.pending_read(origin)!=value:raise StoreError('secure_pending_write_failed')
    def pending_clear(self,origin,expected_tag):
        old=self.pending_read(origin)
        if old is None:return
        if pending_tag(old)!=expected_tag:raise StoreError('pending_pairing_changed')
        try:self._native().delete('com.chiluco.figma-skill|'+origin,'figma-kanpu-totonoe.pending',expected_tag)
        except Exception:raise StoreError('secure_pending_clear_failed') from None
        if self.pending_read(origin) is not None:raise StoreError('secure_pending_clear_failed')

class _NativeKeychain:
    """Independent opt-in SecItem wrapper; live behavior unverified. Guarded tests inject a bridge."""
    def __init__(self):
        if sys.platform!='darwin':raise StoreError('unsupported_secure_store')
        V=ctypes.c_void_p;I=ctypes.c_long
        self.cf=ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sec=ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
        def sig(lib,name,args,result):f=getattr(lib,name);f.argtypes=args;f.restype=result;return f
        sig(self.cf,'CFStringCreateWithCString',[V,ctypes.c_char_p,ctypes.c_uint32],V)
        sig(self.cf,'CFDataCreate',[V,V,I],V);sig(self.cf,'CFDictionaryCreate',[V,ctypes.POINTER(V),ctypes.POINTER(V),I,V,V],V)
        sig(self.cf,'CFRelease',[V],None);sig(self.cf,'CFGetTypeID',[V],ctypes.c_ulong);sig(self.cf,'CFDataGetTypeID',[],ctypes.c_ulong)
        sig(self.cf,'CFDataGetLength',[V],I);sig(self.cf,'CFDataGetBytePtr',[V],V)
        sig(self.sec,'SecItemCopyMatching',[V,ctypes.POINTER(V)],ctypes.c_int32);sig(self.sec,'SecItemAdd',[V,ctypes.POINTER(V)],ctypes.c_int32);sig(self.sec,'SecItemDelete',[V],ctypes.c_int32)
    def const(self,name,lib=None):return ctypes.c_void_p.in_dll(lib or self.sec,name).value
    def query(self,service,account,value=None,read=False,tag=None):
        refs=[]
        def string(s):v=self.cf.CFStringCreateWithCString(None,s.encode(),0x08000100);refs.append(v);return v
        pairs=[(self.const('kSecClass'),self.const('kSecClassGenericPassword')),(self.const('kSecAttrService'),string(service)),(self.const('kSecAttrAccount'),string(account)),(self.const('kSecAttrSynchronizable'),self.const('kCFBooleanFalse',self.cf)),(self.const('kSecUseAuthenticationUI'),self.const('kSecUseAuthenticationUIFail'))]
        if tag is not None:
            b=tag.encode('ascii');buf=ctypes.create_string_buffer(b);t=self.cf.CFDataCreate(None,ctypes.cast(buf,ctypes.c_void_p),len(b));refs.append(t);pairs.append((self.const('kSecAttrGeneric'),t))
        if read:pairs.extend([(self.const('kSecReturnData'),self.const('kCFBooleanTrue',self.cf)),(self.const('kSecMatchLimit'),self.const('kSecMatchLimitOne'))])
        elif value is not None:
            b=value.encode();buf=ctypes.create_string_buffer(b);data=self.cf.CFDataCreate(None,ctypes.cast(buf,ctypes.c_void_p),len(b));refs.append(data);pairs.append((self.const('kSecValueData'),data))
        keys=(ctypes.c_void_p*len(pairs))(*(k for k,v in pairs));vals=(ctypes.c_void_p*len(pairs))(*(v for k,v in pairs));q=self.cf.CFDictionaryCreate(None,keys,vals,len(pairs),None,None)
        if not q:raise StoreError('secure_store_unavailable')
        return q,refs
    def read(self,service,account):
        q,refs=self.query(service,account,read=True);out=ctypes.c_void_p()
        try:
            status=self.sec.SecItemCopyMatching(q,ctypes.byref(out))
            if status==-25300:return None # Only item-not-found; permissions/cancel/locked are failures.
            if status!=0 or not out.value:raise StoreError('secure_store_unavailable')
            if self.cf.CFGetTypeID(out)!=self.cf.CFDataGetTypeID():raise StoreError('secure_store_unavailable')
            n=self.cf.CFDataGetLength(out)
            if not 32<=n<=4096:raise StoreError('invalid_credential')
            return ctypes.string_at(self.cf.CFDataGetBytePtr(out),n).decode('ascii')
        finally:
            if out.value:self.cf.CFRelease(out)
            self.cf.CFRelease(q)
            for r in refs:self.cf.CFRelease(r)
    def add(self,service,account,value,tag=None):
        q,refs=self.query(service,account,value=value,tag=tag)
        try:
            if self.sec.SecItemAdd(q,None)!=0:raise StoreError('secure_store_write_failed')
        finally:
            self.cf.CFRelease(q)
            for r in refs:self.cf.CFRelease(r)

    def delete(self,service,account,tag):
        # Narrow deletion of this pending item/version only, never the actual credential item.
        if account!='figma-kanpu-totonoe.pending' or not re.fullmatch(r'[a-f0-9]{64}',tag):raise StoreError('invalid_pending_scope')
        q,refs=self.query(service,account,tag=tag)
        try:
            if self.sec.SecItemDelete(q) not in (0,-25300):raise StoreError('secure_pending_clear_failed')
        finally:
            self.cf.CFRelease(q)
            for r in refs:self.cf.CFRelease(r)
