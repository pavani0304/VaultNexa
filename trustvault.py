import io, os, sqlite3, uuid, secrets
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, redirect, url_for, flash, render_template_string, send_file, abort, g, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'trustvault_data'
FILES = DATA / 'encrypted_documents'
DB_PATH = DATA / 'trustvault.db'
KEY_PATH = DATA / '.vault_key'
SECRET_PATH = DATA / '.flask_secret'
MAX_SIZE = 20 * 1024 * 1024
ALLOWED = {'pdf','doc','docx','txt','rtf','odt','png','jpg','jpeg','gif','webp','csv','xlsx','xls','ppt','pptx'}
DATA.mkdir(exist_ok=True); FILES.mkdir(exist_ok=True)

def secret_file(path, generator):
    if not path.exists():
        value = generator()
        if isinstance(value, str):
            value = value.encode("utf-8")
        path.write_bytes(value)
    return path.read_bytes()


CIPHER = Fernet(secret_file(KEY_PATH, Fernet.generate_key))
app = Flask(__name__)
app.config.update(SECRET_KEY=secret_file(SECRET_PATH, lambda: secrets.token_hex(32)).decode(), MAX_CONTENT_LENGTH=MAX_SIZE,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('TRUSTVAULT_HTTPS') == '1')
login_manager = LoginManager(app); login_manager.login_view = 'login'

def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH); g.db.row_factory = sqlite3.Row; g.db.execute('PRAGMA foreign_keys=ON')
    return g.db
@app.teardown_appcontext
def close_db(_e=None):
    c = g.pop('db', None)
    if c: c.close()

def init_db():
    c = sqlite3.connect(DB_PATH); c.execute('PRAGMA foreign_keys=ON')
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', active INTEGER NOT NULL DEFAULT 1, must_change INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_seen TEXT);
    CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), original_name TEXT NOT NULL, storage_name TEXT UNIQUE NOT NULL, content_type TEXT, size_bytes INTEGER NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS shares(id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, permission TEXT NOT NULL CHECK(permission IN ('view','download','view_download')), created_at TEXT NOT NULL, UNIQUE(document_id,user_id));
    CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, username TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL, ip TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id); CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id); CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at);
    ''')
    if not c.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone():
        c.execute('INSERT INTO users(username,password_hash,role,active,must_change,created_at) VALUES(?,?,?,?,?,?)', ('admin',generate_password_hash('ChangeMe123!'),'admin',1,1,now())); c.commit()
        print('\nTrustVault first-run admin: username=admin | temporary password=ChangeMe123!\nChange it immediately after login.\n')
    c.commit(); c.close()

class User(UserMixin):
    def __init__(self, row): self.id=str(row['id']); self.username=row['username']; self.role=row['role']; self.active=bool(row['active']); self.must_change=bool(row['must_change'])
    @property
    def is_active(self): return self.active
@login_manager.user_loader
def load_user(uid):
    r=db().execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone(); return User(r) if r else None

def audit(action, details='', actor=None):
    actor = actor or (current_user if current_user.is_authenticated else None)
    username = actor.username if actor else 'anonymous'; uid=int(actor.id) if actor else None
    ip=(request.remote_addr or 'unknown')[:100]
    db().execute('INSERT INTO audit_logs(user_id,username,action,details,ip,created_at) VALUES(?,?,?,?,?,?)',(uid,username,action,str(details)[:500],ip,now())); db().commit()
def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*a,**kw):
        if current_user.role!='admin': audit('ACCESS_DENIED',f'Non-admin attempted {request.path}'); abort(403)
        return fn(*a,**kw)
    return wrapped
@app.before_request
def activity():
    if current_user.is_authenticated:
        db().execute('UPDATE users SET last_seen=? WHERE id=?',(now(),int(current_user.id))); db().commit()
def get_doc(doc_id):
    return db().execute('SELECT d.*,u.username owner FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?',(doc_id,)).fetchone()
def shared_permission(doc_id, uid):
    r=db().execute('SELECT permission FROM shares WHERE document_id=? AND user_id=?',(doc_id,uid)).fetchone(); return r['permission'] if r else None
def can(doc, action):
    if int(doc['owner_id'])==int(current_user.id): return True
    p=shared_permission(doc['id'],int(current_user.id))
    return p in (('view','view_download') if action=='view' else ('download','view_download'))
def decrypt_doc(doc):
    try: return CIPHER.decrypt((FILES/doc['storage_name']).read_bytes())
    except (OSError,InvalidToken): abort(500, description='Cannot decrypt file. The vault key may be missing.')
def sizefmt(n): return f'{n} B' if n<1024 else (f'{n/1024:.1f} KB' if n<1048576 else f'{n/1048576:.1f} MB')
app.jinja_env.filters['filesize']=sizefmt

BASE = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · TrustVault</title><style>
:root{--navy:#142644;--blue:#3556d4;--ink:#19243a;--muted:#68748b;--line:#e2e8f1;--bg:#f4f7fc}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 Segoe UI,Arial,sans-serif}a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}.top{background:var(--navy);color:white;padding:15px 4%;display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;align-items:center}.brand{font-weight:800;font-size:1.25rem;color:white}.brand span{color:#62dfcf}.nav{display:flex;gap:13px;align-items:center;flex-wrap:wrap}.nav a{color:white;font-size:.92rem}.wrap{max-width:1120px;margin:26px auto;padding:0 16px}.hero{background:linear-gradient(120deg,#182b4a,#3557bf);color:white;padding:25px;border-radius:16px;margin-bottom:18px}.hero h1{margin:0 0 8px}.hero p{margin:0;color:#e3eaff}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:14px}.card{background:white;border:1px solid var(--line);border-radius:13px;padding:18px;margin-bottom:16px;box-shadow:0 5px 18px #1b2c4a08}.card h2,.card h3{margin-top:0}.muted{color:var(--muted);font-size:.92rem}.stat{font-size:1.8rem;font-weight:800}.pill{display:inline-block;border-radius:99px;padding:3px 9px;background:#edf0ff;color:#2d46a2;font-size:.78rem;font-weight:700}.green{background:#e2f7ec;color:#176c45}.amber{background:#fff2d2;color:#825500}.btn{display:inline-block;border:0;border-radius:8px;padding:9px 13px;background:var(--blue);color:white;font:inherit;cursor:pointer}.btn:hover{text-decoration:none;background:#2945b5}.secondary{background:#e9edfa;color:#253d80}.danger{background:#b42335;color:white}.small{font-size:.85rem;padding:6px 9px}.field{margin:12px 0}.field label{display:block;font-weight:700;font-size:.9rem;margin-bottom:5px}input,select{font:inherit;padding:10px 11px;border:1px solid #cbd4e2;border-radius:8px;width:100%;background:white}.inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.inline input,.inline select{flex:1;min-width:130px;width:auto}table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:.8rem;text-transform:uppercase;color:var(--muted)}.table-wrap{overflow-x:auto}.empty{padding:22px;text-align:center;color:var(--muted);border:1px dashed #cbd4e2;border-radius:10px}.flash{background:#e4f7ed;color:#176c45;border-radius:8px;padding:11px 14px;margin:10px 0}.flash.error{background:#fff0f0;color:#a11c2d}.notice{background:#fff6dc;color:#704b00;padding:12px;border-radius:8px}.auth{max-width:460px;margin:40px auto}.actions{display:flex;gap:10px;flex-wrap:wrap}.footer{text-align:center;color:var(--muted);padding:24px;font-size:.82rem}@media(max-width:600px){.wrap{margin:16px auto;padding:0 10px}.hero{padding:19px}.card{padding:14px}th,td{padding:8px}}
</style></head><body><header class="top"><a class="brand" href="{{ url_for('dashboard') if current_user.is_authenticated else url_for('home') }}">🔐 Trust<span>Vault</span></a><nav class="nav">{% if current_user.is_authenticated %}<a href="{{ url_for('dashboard') }}">Dashboard</a><a href="{{ url_for('documents') }}">My documents</a><a href="{{ url_for('shared') }}">Shared with me</a>{% if current_user.role=='admin' %}<a href="{{ url_for('admin') }}">Admin</a><a href="{{ url_for('audit_logs') }}">Audit logs</a>{% endif %}<span>{{ current_user.username }}</span><a href="{{ url_for('logout') }}">Log out</a>{% else %}<a href="{{ url_for('login') }}">Log in</a><a href="{{ url_for('register') }}">Register</a>{% endif %}</nav></header><main class="wrap">{% with ms=get_flashed_messages(with_categories=true) %}{% for c,m in ms %}<div class="flash {{ 'error' if c=='error' else '' }}">{{ m }}</div>{% endfor %}{% endwith %}{{ body|safe }}</main><footer class="footer">TrustVault · Secure document sharing prototype · {{ year }}</footer></body></html>'''
def page(title, body, **ctx): return render_template_string(BASE,title=title,body=render_template_string(body,**ctx),year=datetime.now().year)

@app.route('/')
def home():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return page('Welcome', '''<section class="hero"><h1>Documents, shared with trust.</h1><p>Store documents, choose who can access them, and track important actions.</p></section><div class="grid"><section class="card"><h3>🔑 Permission-based sharing</h3><p class="muted">Owners choose view-only, download-only, or both.</p></section><section class="card"><h3>🛡️ Encrypted storage</h3><p class="muted">Files are encrypted before they are saved locally.</p></section><section class="card"><h3>📋 Admin audit trail</h3><p class="muted">Admins can review sign-ins, file activity, and sharing changes.</p></section></div><section class="card"><h2>Get started</h2><div class="actions"><a class="btn" href="{{ url_for('register') }}">Create account</a><a class="btn secondary" href="{{ url_for('login') }}">Log in</a></div></section><p class="muted">Use sample documents only until production security and hosting are configured.</p>''')

@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:return redirect(url_for('dashboard'))
    if request.method=='POST':
        u=request.form.get('username','').strip(); p=request.form.get('password',''); c=request.form.get('confirm','')
        if len(u)<3 or len(u)>30 or not u.replace('_','').isalnum(): flash('Username must be 3–30 letters, numbers, or underscores.','error')
        elif len(p)<10: flash('Password must be at least 10 characters.','error')
        elif p!=c: flash('Passwords do not match.','error')
        else:
            try:
                db().execute('INSERT INTO users(username,password_hash,role,active,must_change,created_at) VALUES(?,?,?,?,?,?)',(u,generate_password_hash(p),'user',1,0,now())); db().commit()
                row=db().execute('SELECT * FROM users WHERE username=?',(u,)).fetchone(); audit('REGISTER','New user registered',User(row)); flash('Account created. Please log in.','success'); return redirect(url_for('login'))
            except sqlite3.IntegrityError: db().rollback(); flash('Username already exists.','error')
    return page('Register','''<section class="auth card"><h1>Create account</h1><p class="muted">Documents are private unless you share them.</p><form method="post"><div class="field"><label>Username</label><input name="username" required minlength="3" maxlength="30"></div><div class="field"><label>Password (10+ characters)</label><input type="password" name="password" required minlength="10"></div><div class="field"><label>Confirm password</label><input type="password" name="confirm" required minlength="10"></div><button class="btn">Create account</button></form></section>''')

@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated:return redirect(url_for('change_password') if current_user.must_change else url_for('dashboard'))
    if request.method=='POST':
        u=request.form.get('username','').strip(); p=request.form.get('password',''); r=db().execute('SELECT * FROM users WHERE username=? COLLATE NOCASE',(u,)).fetchone()
        if r and r['active'] and check_password_hash(r['password_hash'],p):
            user=User(r); login_user(user); session.permanent=True; audit('LOGIN_SUCCESS','User logged in',user)
            if user.must_change: flash('Change the temporary admin password first.','error'); return redirect(url_for('change_password'))
            flash('Login successful.','success'); return redirect(url_for('dashboard'))
        audit('LOGIN_FAILED',f'Failed login attempt for username: {u[:60]}'); flash('Login failed. Check credentials or account status.','error')
    return page('Log in','''<section class="auth card"><h1>Log in</h1><form method="post"><div class="field"><label>Username</label><input name="username" required autocomplete="username"></div><div class="field"><label>Password</label><input type="password" name="password" required autocomplete="current-password"></div><button class="btn">Log in</button></form><p class="muted">New user? <a href="{{ url_for('register') }}">Create an account</a>.</p></section>''')

@app.route('/change-password',methods=['GET','POST'])
@login_required
def change_password():
    if request.method=='POST':
        old=request.form.get('old',''); new=request.form.get('new',''); confirm=request.form.get('confirm',''); r=db().execute('SELECT password_hash FROM users WHERE id=?',(int(current_user.id),)).fetchone()
        if not check_password_hash(r['password_hash'],old):flash('Current password is incorrect.','error')
        elif len(new)<12:flash('New password must be at least 12 characters.','error')
        elif new!=confirm:flash('New passwords do not match.','error')
        elif old==new:flash('Choose a different password.','error')
        else:
            db().execute('UPDATE users SET password_hash=?,must_change=0 WHERE id=?',(generate_password_hash(new),int(current_user.id)));db().commit();audit('PASSWORD_CHANGED','Password changed');flash('Password changed.','success');return redirect(url_for('dashboard'))
    return page('Change password','''<section class="auth card"><h1>Change password</h1><p class="notice">The first-run admin must change the temporary password before continuing.</p><form method="post"><div class="field"><label>Current password</label><input type="password" name="old" required></div><div class="field"><label>New password (12+ characters)</label><input type="password" name="new" minlength="12" required></div><div class="field"><label>Confirm new password</label><input type="password" name="confirm" minlength="12" required></div><button class="btn">Update password</button></form></section>''')

@app.route('/logout')
@login_required
def logout(): audit('LOGOUT','User logged out');logout_user();flash('Logged out.','success');return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.must_change:return redirect(url_for('change_password'))
    uid=int(current_user.id); own=db().execute('SELECT COUNT(*) n FROM documents WHERE owner_id=?',(uid,)).fetchone()['n']; shared_n=db().execute('SELECT COUNT(*) n FROM shares WHERE user_id=?',(uid,)).fetchone()['n']; rows=db().execute('SELECT d.*,(SELECT COUNT(*) FROM shares s WHERE s.document_id=d.id) share_count FROM documents d WHERE owner_id=? ORDER BY id DESC LIMIT 5',(uid,)).fetchall()
    return page('Dashboard','''<section class="hero"><h1>Welcome, {{ current_user.username }}.</h1><p>Your private document workspace with controlled sharing.</p></section><div class="grid"><section class="card"><div class="muted">Documents you own</div><div class="stat">{{ own }}</div></section><section class="card"><div class="muted">Shared with you</div><div class="stat">{{ shared_n }}</div></section><section class="card"><div class="muted">Account status</div><div class="stat" style="font-size:1.3rem">Active</div><span class="pill green">Protected workspace</span></section></div><section class="card"><div class="inline" style="justify-content:space-between"><h2>Recent documents</h2><a class="btn" href="{{ url_for('documents') }}">Manage documents</a></div>{% if rows %}<div class="table-wrap"><table><tr><th>Document</th><th>Uploaded</th><th>Shares</th><th>Action</th></tr>{% for d in rows %}<tr><td>{{ d.original_name }}</td><td>{{ d.created_at }}</td><td>{{ d.share_count }}</td><td><a href="{{ url_for('manage_doc',doc_id=d.id) }}">Manage access</a></td></tr>{% endfor %}</table></div>{% else %}<div class="empty">No documents yet. Upload your first file.</div>{% endif %}</section>''',own=own,shared_n=shared_n,rows=rows)

@app.route('/documents',methods=['GET','POST'])
@login_required
def documents():
    if current_user.must_change:return redirect(url_for('change_password'))
    if request.method=='POST':
        f=request.files.get('file')
        if not f or not f.filename:flash('Choose a file first.','error')
        else:
            name=secure_filename(f.filename); ext=name.rsplit('.',1)[-1].lower() if '.' in name else ''
            data=f.read(MAX_SIZE+1)
            if not name or ext not in ALLOWED:flash('File type not allowed. Use PDF, Office, text, image, CSV, or spreadsheet files.','error')
            elif len(data)>MAX_SIZE:flash('Maximum upload size is 20 MB.','error')
            elif not data:flash('Empty files cannot be uploaded.','error')
            else:
                stored=uuid.uuid4().hex+'.enc'
                try:
                    (FILES/stored).write_bytes(CIPHER.encrypt(data));db().execute('INSERT INTO documents(owner_id,original_name,storage_name,content_type,size_bytes,created_at) VALUES(?,?,?,?,?,?)',(int(current_user.id),name,stored,f.mimetype or 'application/octet-stream',len(data),now()));db().commit();audit('DOCUMENT_UPLOAD',f'Uploaded {name}');flash('Document uploaded and encrypted.','success');return redirect(url_for('documents'))
                except Exception: (FILES/stored).unlink(missing_ok=True);db().rollback();app.logger.exception('Upload failed');flash('Upload failed.','error')
    q=request.args.get('q','')[:100]; rows=db().execute('SELECT d.*,(SELECT COUNT(*) FROM shares s WHERE s.document_id=d.id) share_count FROM documents d WHERE owner_id=? AND original_name LIKE ? ORDER BY id DESC',(int(current_user.id),f'%{q}%')).fetchall()
    return page('My documents','''<section class="hero"><h1>My documents</h1><p>Files are encrypted before storage. You decide who can access each document.</p></section><section class="card"><h2>Upload a document</h2><p class="muted">Maximum 20 MB. Supported: PDF, Office, text, images, CSV, spreadsheets.</p><form method="post" enctype="multipart/form-data"><div class="field"><input type="file" name="file" required></div><button class="btn">Upload securely</button></form></section><section class="card"><div class="inline" style="justify-content:space-between"><h2>Your files ({{ rows|length }})</h2><form class="inline" method="get"><input name="q" value="{{ q }}" placeholder="Search filenames"><button class="btn secondary">Search</button></form></div>{% if rows %}<div class="table-wrap"><table><tr><th>Document</th><th>Size</th><th>Uploaded</th><th>Shares</th><th>Actions</th></tr>{% for d in rows %}<tr><td>📄 {{ d.original_name }}</td><td>{{ d.size_bytes|filesize }}</td><td>{{ d.created_at }}</td><td>{{ d.share_count }}</td><td><div class="actions"><a href="{{ url_for('manage_doc',doc_id=d.id) }}">Manage sharing</a><a href="{{ url_for('download_doc',doc_id=d.id) }}">Download</a></div></td></tr>{% endfor %}</table></div>{% else %}<div class="empty">No matching documents. Upload a file to begin.</div>{% endif %}</section>''',rows=rows,q=q)

@app.route('/documents/<int:doc_id>')
@login_required
def manage_doc(doc_id):
    d=get_doc(doc_id)
    if not d:abort(404)
    if int(d['owner_id'])!=int(current_user.id):audit('ACCESS_DENIED',f'Manage document {doc_id}');abort(403)
    shares=db().execute('SELECT s.*,u.username FROM shares s JOIN users u ON u.id=s.user_id WHERE s.document_id=? ORDER BY u.username',(doc_id,)).fetchall(); users=db().execute("SELECT id,username FROM users WHERE role='user' AND active=1 AND id!=? ORDER BY username",(int(current_user.id),)).fetchall()
    return page('Manage access','''<section class="hero"><h1>Manage access</h1><p>Document: <strong>{{ d.original_name }}</strong> · Owner: {{ current_user.username }}</p></section><section class="card"><p><strong>Size:</strong> {{ d.size_bytes|filesize }} · <strong>Encrypted at rest:</strong> <span class="pill green">Yes</span></p><div class="actions"><a class="btn secondary" href="{{ url_for('preview_doc',doc_id=d.id) }}">Preview</a><a class="btn secondary" href="{{ url_for('download_doc',doc_id=d.id) }}">Download</a><a class="btn secondary" href="{{ url_for('documents') }}">Back</a></div></section><section class="card"><h2>Share with a user</h2>{% if users %}<form method="post" action="{{ url_for('share_doc',doc_id=d.id) }}"><div class="field"><label>User</label><select name="username" required><option value="">Choose user</option>{% for u in users %}<option>{{ u.username }}</option>{% endfor %}</select></div><div class="field"><label>Permission</label><select name="permission"><option value="view">View only</option><option value="download">Download only</option><option value="view_download">View and download</option></select></div><button class="btn">Grant access</button></form>{% else %}<div class="empty">Create another user account before testing sharing.</div>{% endif %}</section><section class="card"><h2>Current access</h2>{% if shares %}<div class="table-wrap"><table><tr><th>User</th><th>Permission</th><th>Granted</th><th>Action</th></tr>{% for s in shares %}<tr><td>{{ s.username }}</td><td>{{ {'view':'View only','download':'Download only','view_download':'View and download'}[s.permission] }}</td><td>{{ s.created_at }}</td><td><form method="post" action="{{ url_for('revoke_doc',doc_id=d.id,share_id=s.id) }}"><button class="btn danger small">Revoke</button></form></td></tr>{% endfor %}</table></div>{% else %}<div class="empty">Not shared with anyone.</div>{% endif %}</section><section class="card"><h2>Delete document</h2><p class="muted">This permanently removes the encrypted file and access grants.</p><form method="post" action="{{ url_for('delete_doc',doc_id=d.id) }}" onsubmit="return confirm('Delete this document permanently?')"><button class="btn danger">Delete document</button></form></section>''',d=d,shares=shares,users=users)

@app.route('/documents/<int:doc_id>/share',methods=['POST'])
@login_required
def share_doc(doc_id):
    d=get_doc(doc_id)
    if not d:abort(404)
    if int(d['owner_id'])!=int(current_user.id):audit('ACCESS_DENIED',f'Share document {doc_id}');abort(403)
    target=db().execute("SELECT * FROM users WHERE username=? COLLATE NOCASE",(request.form.get('username','').strip(),)).fetchone(); p=request.form.get('permission')
    if p not in ('view','download','view_download') or not target or not target['active'] or target['role']!='user':flash('Choose a valid active user and permission.','error')
    else:
        db().execute('INSERT INTO shares(document_id,user_id,permission,created_at) VALUES(?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,created_at=excluded.created_at',(doc_id,target['id'],p,now()));db().commit();audit('DOCUMENT_SHARED',f'{d["original_name"]} shared with {target["username"]}: {p}');flash('Access granted or updated.','success')
    return redirect(url_for('manage_doc',doc_id=doc_id))
@app.route('/documents/<int:doc_id>/share/<int:share_id>/revoke',methods=['POST'])
@login_required
def revoke_doc(doc_id,share_id):
    d=get_doc(doc_id)
    if not d:abort(404)
    if int(d['owner_id'])!=int(current_user.id):abort(403)
    s=db().execute('SELECT s.id,u.username FROM shares s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.document_id=?',(share_id,doc_id)).fetchone()
    if s:db().execute('DELETE FROM shares WHERE id=?',(share_id,));db().commit();audit('SHARE_REVOKED',f'Revoked {s["username"]} from {d["original_name"]}');flash('Access revoked.','success')
    return redirect(url_for('manage_doc',doc_id=doc_id))
@app.route('/documents/<int:doc_id>/preview')
@login_required
def preview_doc(doc_id):
    d=get_doc(doc_id)
    if not d:abort(404)
    if not can(d,'view'):audit('ACCESS_DENIED',f'View denied for document {doc_id}');abort(403)
    data=decrypt_doc(d);audit('DOCUMENT_VIEW',f'Viewed {d["original_name"]}');return send_file(io.BytesIO(data),mimetype=d['content_type'] or 'application/octet-stream',as_attachment=False,download_name=d['original_name'],max_age=0)
@app.route('/documents/<int:doc_id>/download')
@login_required
def download_doc(doc_id):
    d=get_doc(doc_id)
    if not d:abort(404)
    if not can(d,'download'):audit('ACCESS_DENIED',f'Download denied for document {doc_id}');abort(403)
    data=decrypt_doc(d);audit('DOCUMENT_DOWNLOAD',f'Downloaded {d["original_name"]}');return send_file(io.BytesIO(data),mimetype=d['content_type'] or 'application/octet-stream',as_attachment=True,download_name=d['original_name'],max_age=0)
@app.route('/documents/<int:doc_id>/delete',methods=['POST'])
@login_required
def delete_doc(doc_id):
    d=get_doc(doc_id)
    if not d:abort(404)
    if int(d['owner_id'])!=int(current_user.id):abort(403)
    (FILES/d['storage_name']).unlink(missing_ok=True);db().execute('DELETE FROM documents WHERE id=?',(doc_id,));db().commit();audit('DOCUMENT_DELETED',f'Deleted {d["original_name"]}');flash('Document deleted.','success');return redirect(url_for('documents'))

@app.route('/shared')
@login_required
def shared():
    rows=db().execute('SELECT d.*,u.username owner,s.permission,s.created_at shared_at FROM shares s JOIN documents d ON d.id=s.document_id JOIN users u ON u.id=d.owner_id WHERE s.user_id=? AND u.active=1 ORDER BY s.id DESC',(int(current_user.id),)).fetchall()
    return page('Shared with me','''<section class="hero"><h1>Shared with me</h1><p>Actions available depend on the permission the owner granted.</p></section><section class="card"><h2>Shared documents ({{ rows|length }})</h2>{% if rows %}<div class="table-wrap"><table><tr><th>Document</th><th>Owner</th><th>Permission</th><th>Shared on</th><th>Actions</th></tr>{% for d in rows %}<tr><td>{{ d.original_name }}</td><td>{{ d.owner }}</td><td>{{ {'view':'View only','download':'Download only','view_download':'View and download'}[d.permission] }}</td><td>{{ d.shared_at }}</td><td class="actions">{% if d.permission in ['view','view_download'] %}<a href="{{ url_for('preview_doc',doc_id=d.id) }}">Preview</a>{% endif %}{% if d.permission in ['download','view_download'] %}<a href="{{ url_for('download_doc',doc_id=d.id) }}">Download</a>{% endif %}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">No documents shared with you yet.</div>{% endif %}</section>''',rows=rows)

@app.route('/admin')
@admin_required
def admin():
    c=db(); users=c.execute("SELECT * FROM users WHERE role='user' ORDER BY created_at DESC").fetchall(); uc=c.execute("SELECT COUNT(*) n FROM users WHERE role='user'").fetchone()['n']; active=c.execute("SELECT COUNT(*) n FROM users WHERE role='user' AND active=1").fetchone()['n']; docs=c.execute('SELECT COUNT(*) n FROM documents').fetchone()['n']; shares=c.execute('SELECT COUNT(*) n FROM shares').fetchone()['n']; shared_docs=c.execute('SELECT COUNT(DISTINCT document_id) n FROM shares').fetchone()['n']; owners=c.execute('SELECT COUNT(DISTINCT owner_id) n FROM documents').fetchone()['n']; since=(datetime.now()-timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'); online=c.execute("SELECT username,last_seen FROM users WHERE role='user' AND active=1 AND last_seen>=? ORDER BY last_seen DESC",(since,)).fetchall(); recent=c.execute('SELECT d.*,u.username owner,(SELECT COUNT(*) FROM shares s WHERE s.document_id=d.id) share_count FROM documents d JOIN users u ON u.id=d.owner_id ORDER BY d.id DESC LIMIT 15').fetchall()
    return page('Admin dashboard','''<section class="hero"><h1>Administrator dashboard</h1><p>Monitor users, document owners, shared files, access grants, and recent activity. Audit logs are admin-only.</p></section><div class="grid"><section class="card"><div class="muted">Registered users</div><div class="stat">{{ uc }}</div><div class="muted">{{ active }} active</div></section><section class="card"><div class="muted">Total documents</div><div class="stat">{{ docs_n }}</div><div class="muted">{{ owners }} owners</div></section><section class="card"><div class="muted">Documents shared</div><div class="stat">{{ shared_docs }}</div><div class="muted">{{ shares }} user access grants</div></section><section class="card"><div class="muted">Recently active users</div><div class="stat">{{ online|length }}</div><div class="muted">Activity in last 5 minutes (approx.)</div></section></div><section class="card"><div class="inline" style="justify-content:space-between"><h2>User management</h2><a class="btn secondary" href="{{ url_for('audit_logs') }}">View audit logs</a></div><div class="table-wrap"><table><tr><th>User</th><th>Joined</th><th>Last activity</th><th>Status</th><th>Action</th></tr>{% for u in users %}<tr><td>{{ u.username }}</td><td>{{ u.created_at }}</td><td>{{ u.last_seen or 'Never' }}</td><td>{{ 'Active' if u.active else 'Disabled' }}</td><td><form method="post" action="{{ url_for('toggle_user',uid=u.id) }}"><button class="btn {{ 'danger' if u.active else 'secondary' }} small">{{ 'Disable' if u.active else 'Enable' }}</button></form></td></tr>{% else %}<tr><td colspan="5">No user accounts yet.</td></tr>{% endfor %}</table></div></section><section class="card"><h2>Document owners and sharing</h2>{% if recent %}<div class="table-wrap"><table><tr><th>Document</th><th>Owner</th><th>Uploaded</th><th>Size</th><th>Shared users</th></tr>{% for d in recent %}<tr><td>{{ d.original_name }}</td><td>{{ d.owner }}</td><td>{{ d.created_at }}</td><td>{{ d.size_bytes|filesize }}</td><td>{{ d.share_count }}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">No documents uploaded.</div>{% endif %}</section><section class="card"><h2>Recently active users</h2>{% if online %}<ul>{% for u in online %}<li>{{ u.username }} — {{ u.last_seen }}</li>{% endfor %}</ul>{% else %}<p class="muted">No activity in the last five minutes.</p>{% endif %}<p class="muted">This is approximate recent activity, not a live connection indicator.</p></section>''',uc=uc,active=active,docs_n=docs,shares=shares,shared_docs=shared_docs,owners=owners,online=online,users=users,recent=recent)
@app.route('/admin/users/<int:uid>/toggle',methods=['POST'])
@admin_required
def toggle_user(uid):
    u=db().execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
    if not u or u['role']=='admin':abort(404)
    value=0 if u['active'] else 1;db().execute('UPDATE users SET active=? WHERE id=?',(value,uid));db().commit();audit('USER_ENABLED' if value else 'USER_DISABLED',f'Admin changed status of {u["username"]}');flash(f'User {u["username"]} updated.','success');return redirect(url_for('admin'))
@app.route('/admin/audit')
@admin_required
def audit_logs():
    act=request.args.get('action','')[:60]; q=request.args.get('q','')[:100]; rows=db().execute('SELECT * FROM audit_logs WHERE action LIKE ? AND (username LIKE ? OR details LIKE ? OR ip LIKE ?) ORDER BY id DESC LIMIT 300',(f'%{act}%',f'%{q}%',f'%{q}%',f'%{q}%')).fetchall(); actions=db().execute('SELECT DISTINCT action FROM audit_logs ORDER BY action').fetchall()
    return page('Audit logs','''<section class="hero"><h1>Admin-only audit logs</h1><p>Track login attempts, uploads, views, downloads, sharing, revocation, and denied access. Latest 300 matching events are shown.</p></section><section class="card"><form class="inline" method="get"><select name="action"><option value="">All actions</option>{% for a in actions %}<option value="{{ a.action }}" {{ 'selected' if act==a.action else '' }}>{{ a.action }}</option>{% endfor %}</select><input name="q" value="{{ q }}" placeholder="Search user, details, IP"><button class="btn">Filter</button><a class="btn secondary" href="{{ url_for('audit_logs') }}">Reset</a></form></section><section class="card"><h2>Records ({{ rows|length }})</h2>{% if rows %}<div class="table-wrap"><table><tr><th>Date/time</th><th>User</th><th>Action</th><th>Details</th><th>IP</th></tr>{% for r in rows %}<tr><td>{{ r.created_at }}</td><td>{{ r.username }}</td><td><span class="pill">{{ r.action }}</span></td><td>{{ r.details }}</td><td>{{ r.ip }}</td></tr>{% endfor %}</table></div>{% else %}<div class="empty">No matching logs.</div>{% endif %}</section>''',rows=rows,actions=actions,act=act,q=q)
@app.errorhandler(403)
def forbidden(_e): return page('Access denied','<section class="card"><h1>Access denied</h1><p>Your account does not have permission to open this page or document.</p><a class="btn" href="{{ url_for(\'dashboard\') }}">Back to dashboard</a></section>'),403
@app.errorhandler(404)
def missing(_e): return page('Not found','<section class="card"><h1>Not found</h1><p>This page or document does not exist.</p><a class="btn" href="{{ url_for(\'dashboard\') }}">Back to dashboard</a></section>'),404
@app.errorhandler(413)
def too_large(_e): return page('File too large','<section class="card"><h1>File too large</h1><p>Maximum upload size is 20 MB.</p><a class="btn" href="{{ url_for(\'documents\') }}">Back to documents</a></section>'),413

init_db()
if __name__=='__main__':
    print('TrustVault running at http://127.0.0.1:5000')
    app.run(host='127.0.0.1',port=5000,debug=False)
