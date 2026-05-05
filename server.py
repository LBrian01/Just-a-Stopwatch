#!/usr/bin/env python3
import json, os, hashlib, uuid, time, datetime
from wsgiref.simple_server import make_server
from urllib.parse import parse_qs
from http.cookies import SimpleCookie

USERS_FILE = 'users.json'
RECORDS_FILE = 'records.txt'
sessions = {}  # session_id -> {'email':..., 'start':epoch}

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE,'r',encoding='utf-8') as f:
        try:
            return json.load(f)
        except:
            return {}

def save_users(u):
    with open(USERS_FILE,'w',encoding='utf-8') as f:
        json.dump(u,f,ensure_ascii=False)

def hashpw(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def serve_static(path):
    root = os.path.dirname(__file__)
    p = os.path.join(root, path.lstrip('/'))
    if not os.path.exists(p):
        return None, None
    ct = 'text/plain; charset=utf-8'
    if p.endswith('.html'): ct = 'text/html; charset=utf-8'
    elif p.endswith('.css'): ct = 'text/css; charset=utf-8'
    elif p.endswith('.js'): ct = 'application/javascript; charset=utf-8'
    with open(p,'rb') as f:
        return ct, f.read()

def get_cookie(environ):
    cookie = SimpleCookie()
    if 'HTTP_COOKIE' in environ:
        cookie.load(environ['HTTP_COOKIE'])
    return cookie

def parse_json_body(environ):
    try:
        length = int(environ.get('CONTENT_LENGTH') or 0)
    except:
        length = 0
    if length == 0:
        return {}
    body = environ['wsgi.input'].read(length)
    try:
        return json.loads(body.decode('utf-8'))
    except:
        return {}

def json_resp(start_response, data, status='200 OK', headers=None):
    b = json.dumps(data, ensure_ascii=False).encode('utf-8')
    resp_headers = [('Content-Type','application/json; charset=utf-8'),
                    ('Content-Length', str(len(b)))]
    if headers:
        resp_headers += headers
    start_response(status, resp_headers)
    return [b]

def app(environ, start_response):
    path = environ.get('PATH_INFO','/')
    method = environ.get('REQUEST_METHOD','GET')

    # static files
    if path == '/':
        ct, data = serve_static('index.html')
        if ct is None:
            start_response('404 NOT FOUND', [('Content-Type','text/plain')])
            return [b'']
        start_response('200 OK', [('Content-Type',ct)])
        return [data]
    if path.startswith('/static/'):
        ct, data = serve_static(path.lstrip('/'))
        if ct is None:
            start_response('404 NOT FOUND', [('Content-Type','text/plain')])
            return [b'']
        start_response('200 OK', [('Content-Type',ct)])
        return [data]

    # API: register
    if path == '/register' and method == 'POST':
        body = parse_json_body(environ)
        email = body.get('email','').strip().lower()
        pw = body.get('password','')
        if not email or not pw:
            return json_resp(start_response, {'ok':False,'error':'bad'}, '400 Bad Request')
        users = load_users()
        if email in users:
            return json_resp(start_response, {'ok':False,'error':'exists'}, '409 Conflict')
        users[email] = hashpw(pw)
        save_users(users)
        return json_resp(start_response, {'ok':True})

    # API: login
    if path == '/login' and method == 'POST':
        body = parse_json_body(environ)
        email = body.get('email','').strip().lower()
        pw = body.get('password','')
        users = load_users()
        if email in users and users[email] == hashpw(pw):
            sid = uuid.uuid4().hex
            start_ts = int(time.time())
            sessions[sid] = {'email':email, 'start': start_ts}
            headers = [('Set-Cookie', f"SESSION_ID={sid}; Path=/; HttpOnly")]
            return json_resp(start_response, {'ok':True, 'logged':True, 'start_time': start_ts}, headers=headers)
        else:
            return json_resp(start_response, {'ok':False,'logged':False}, '401 Unauthorized')

    # API: session status
    if path == '/session' and method == 'GET':
        cookie = get_cookie(environ)
        sid = cookie.get('SESSION_ID').value if cookie.get('SESSION_ID') else None
        if sid and sid in sessions:
            s = sessions[sid]
            return json_resp(start_response, {'logged':True, 'email':s['email'], 'start_time': s['start']})
        else:
            return json_resp(start_response, {'logged':False})

    # API: logout (save record)
    if path == '/logout' and method == 'POST':
        cookie = get_cookie(environ)
        sid = cookie.get('SESSION_ID').value if cookie.get('SESSION_ID') else None
        if sid and sid in sessions:
            s = sessions.pop(sid)
            now = int(time.time())
            elapsed = max(0, now - s['start'])
            # 保存记录：邮箱 | 开始 | 结束 | elapsed秒
            start_iso = datetime.datetime.utcfromtimestamp(s['start']).isoformat() + 'Z'
            end_iso = datetime.datetime.utcfromtimestamp(now).isoformat() + 'Z'
            line = f"{s['email']} | start:{start_iso} | end:{end_iso} | elapsed:{elapsed}s\n"
            with open(RECORDS_FILE,'a',encoding='utf-8') as f:
                f.write(line)
            # 清除 cookie
            headers = [('Set-Cookie', 'SESSION_ID=; Path=/; Max-Age=0; HttpOnly')]
            return json_resp(start_response, {'ok':True}, headers=headers)
        else:
            return json_resp(start_response, {'ok':False,'error':'no session'}, '400 Bad Request')

    start_response('404 NOT FOUND', [('Content-Type','text/plain')])
    return [b'']

if __name__ == '__main__':
    port = int(input("Port:"))
    print(f"Serving on http://localhost:{port}")
    with make_server('', port, app) as httpd:
        httpd.serve_forever()
