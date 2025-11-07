from models.sqlimodel import Classes
from flask import Flask, request, render_template, redirect, make_response, session, url_for
import pickle, base64, hashlib

app = Flask(__name__, static_url_path='/static', static_folder='static')

app.config['DEBUG'] = False
app.config.update(dict(
    SECRET_KEY="redacted",
    SESSION_COOKIE_HTTPONLY=True
))

# Insecure helper for IDOR-ish "hashing" of the user id
def token_for_id(user_id: int) -> str:
    # Intentionally weak and unsalted to keep challenge solvable
    return hashlib.md5(str(user_id).encode()).hexdigest()

def id_from_token(token: str):
    # Resolve an id by brute matching md5(id) == token
    sqli = Classes()
    for uid in sqli.get_all_user_ids():
        if token_for_id(uid) == token:
            return uid
    return None

# Object used for admin checkbox preference persistence in cookie (vulnerable)
class AdminPrefs:
    def __init__(self, target='all'):
        # 'all' or 'selected'; content is irrelevant to the vuln
        self.target = target

@app.route("/")
def index():
    if session.get('loggedin'):
        return render_template("loggedin.html", username=session.get('username'), role=session.get('role'))
    return render_template("index.html")

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    sqli = Classes()
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not username or not email or not password:
            error = "All fields are required."
        else:
            try:
                sqli.create_user(username, email, password)
                return redirect(url_for('login'))
            except Exception as e:
                error = f"Error: {e}"
    return render_template("signup.html", error=error)

@app.route("/login", methods=['GET', 'POST'])
def login():
    sqli = Classes()
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = sqli.get_user_by_username(username)
        if user and user['password'] == password:
            session['username'] = user['username']
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['loggedin'] = True
            sqli.record_login(user['id'])
            return redirect(url_for('index'))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/logout", methods=['POST', 'GET'])
def logout():
    session.clear()
    res = make_response(redirect(url_for('index')))
    # Clear the vulnerable cookie on logout
    res.set_cookie('adminprefs', '', expires=0)
    return res

@app.route("/reset", methods=['GET', 'POST'])
def reset():
    # Step 1: Verify username + email; if correct, render confirm page with a hidden md5(id) token.
    sqli = Classes()
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        user = sqli.get_user_by_username_email(username, email)
        if user:
            uid_token = token_for_id(user['id'])
            # Note: No redirect with uid in URL; token is only in the hidden form field
            return render_template("reset_confirm.html", uid_token=uid_token, message=None, error=None)
        else:
            error = "User not found with that username/email."
    return render_template("reset_start.html", error=error)

@app.route("/reset/confirm", methods=['POST'])
def reset_confirm():
    # Intentional IDOR: server trusts uid_token (md5 of numeric id) from the form
    sqli = Classes()
    error = None
    message = None
    uid_token = request.form.get('uid_token', '')
    new_password = request.form.get('new_password', '')
    if not uid_token or not new_password:
        error = "Missing token or new password."
        return render_template("reset_confirm.html", uid_token=None, message=None, error=error)

    uid = id_from_token(uid_token)
    if uid is None:
        error = "Invalid or expired token."
        return render_template("reset_confirm.html", uid_token=None, message=None, error=error)

    sqli.update_user_password_by_id(uid, new_password)
    message = "Password updated. You can now login."
    return render_template("reset_confirm.html", uid_token=None, message=message, error=None)

@app.route("/admin", methods=['GET', 'POST'])
def admin():
    # Simple admin gate
    if not session.get('loggedin') or session.get('role') != 'admin':
        return redirect(url_for('login'))

    sqli = Classes()
    message = None

    # Vulnerable cookie path: Insecure deserialization happens on any /admin request if cookie present
    if 'adminprefs' in request.cookies:
        try:
            b64 = request.cookies.get('adminprefs')
            _obj = pickle.loads(base64.b64decode(b64))
            # RCE (if any) occurs in __reduce__; we don't need to use _obj
        except Exception:
            # Swallow errors to keep page functional
            pass

    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'reset_last_login':
            all_users_flag = request.form.get('all_users') == 'on'
            if all_users_flag:
                sqli.reset_last_login_all()
                message = "Last login reset to NULL for all users."
            else:
                selected_ids = request.form.getlist('user_ids')
                ids = [int(x) for x in selected_ids if x.isdigit()]
                if ids:
                    sqli.reset_last_login_users(ids)
                    message = f"Last login reset to NULL for {len(ids)} user(s)."
                else:
                    message = "No users selected."

            # After confirmation: SET a benign adminprefs cookie so players see it and can tamper later
            prefs_target = 'all' if all_users_flag else 'selected'
            prefs = AdminPrefs(target=prefs_target)
            ser = pickle.dumps(prefs)
            b64 = base64.b64encode(ser).decode()

            res = make_response(render_template("admin.html", users=sqli.list_users(), message=message))
            res.set_cookie("adminprefs", b64, max_age=60*60*24*7)  # persist 7 days
            return res

    users = sqli.list_users()
    return render_template("admin.html", users=users, message=message)

if __name__ == "__main__":
    app.run(host='0.0.0.0')