"""One-use loopback password field. No secret in arguments, URLs, files or logs."""
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import secrets
import time
from urllib.parse import parse_qs


class InputTimedOut(ValueError):
    pass


def read_code(timeout=600,announce=None):
    csrf=secrets.token_hex(32);received=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def setup(self):
            super().setup();self.connection.settimeout(3)
        def respond(self,status,body):
            self.send_response(status)
            for key,value in {
                'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store',
                # A native POST under no-referrer can send Origin: null.
                'Referrer-Policy':'same-origin','X-Frame-Options':'DENY',
                'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
                'X-Content-Type-Options':'nosniff','Connection':'close'
            }.items():self.send_header(key,value)
            raw=body.encode('utf-8');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def host_ok(self):return self.headers.get('Host')==address
        def do_GET(self):
            if not self.host_ok() or self.path!='/':return self.respond(404,'Not found')
            return self.respond(200,'<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>講座スキルの初回接続</title><style>body{font:16px system-ui;max-width:620px;margin:60px auto;padding:0 24px;line-height:1.8}input{box-sizing:border-box;width:100%;padding:12px;font-size:18px}button{margin-top:20px;padding:12px 22px;font-size:16px}</style><h1>講座スキルの初回接続</h1><p>講座の登録画面に表示された<strong>初回接続コード</strong>を入力してください。メールに届いた確認コードとは別です。</p><p>コードはこのPCの中だけで受け取り、入力欄には表示しません。チャットへ貼る必要はありません。</p><form method="post" action="/pair" autocomplete="off"><input type="hidden" name="csrf" value="'+csrf+'"><label>初回接続コード<input type="password" name="code" required autocomplete="off" spellcheck="false"></label><button type="submit">接続を進める</button></form></html>')
        def do_POST(self):
            if not self.host_ok() or self.path!='/pair' or self.headers.get('Origin')!=origin:
                return self.respond(403,'入力元を確認できません。Codexが案内したURLを開き直してください。')
            raw_length=self.headers.get('Content-Length','')
            if not raw_length.isdigit() or not 1<=int(raw_length)<=2048 or self.headers.get('Content-Type','').split(';',1)[0]!='application/x-www-form-urlencoded':
                return self.respond(400,'入力内容を確認してください。')
            try:
                body=self.rfile.read(int(raw_length)).decode('ascii')
                values=parse_qs(body,strict_parsing=True,keep_blank_values=True,max_num_fields=2)
                if set(values)!={'csrf','code'} or any(len(v)!=1 for v in values.values()) or not hmac.compare_digest(values['csrf'][0],csrf):raise ValueError('invalid')
                code=values['code'][0].strip()
                if not re.fullmatch(r'[a-f0-9]{64}\.[a-f0-9]{64}',code):
                    return self.respond(400,'初回接続コードを確認してください。メールの確認コードではなく、講座の登録画面に表示されたコードを入力します。値は表示・保存していません。戻って入力し直してください。')
            except (ValueError,UnicodeError):return self.respond(400,'入力内容を確認してください。')
            received.append(code)
            self.respond(200,'<!doctype html><html lang="ja"><meta charset="utf-8"><title>入力を受け取りました</title><p>入力を受け取りました。このタブは閉じて大丈夫です。接続と導入の結果はCodexで確認してください。</p></html>')
    with HTTPServer(('127.0.0.1',0),Handler) as server:
        server.timeout=1;address='127.0.0.1:'+str(server.server_port);origin='http://'+address
        if announce is None:
            print(json.dumps({'status':'input_required','url':origin+'/','message':'このPCの非表示入力欄へ、講座の初回接続コードを入力してください。'}),flush=True)
        else:announce(origin+'/')
        end=time.monotonic()+timeout
        while not received and time.monotonic()<end:server.handle_request()
    if not received:raise InputTimedOut('secure_input_timed_out')
    return received[0]
