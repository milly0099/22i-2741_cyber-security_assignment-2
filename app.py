import os
import sqlite3
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import bcrypt
from utils import encrypt_data, decrypt_data, log_activity, validate_email, validate_password_strength
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', secrets.token_hex(32))
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

ALLOWED_UPLOAD_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_INPUT_LENGTH = 1000

def get_db():
    conn = sqlite3.connect('fintech.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            account_balance REAL DEFAULT 0.0,
            encrypted_ssn TEXT,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            encrypted_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            ip_address TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            log_activity(None, 'unauthorized_access_attempt', request.remote_addr, f'Attempted to access {request.path}')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def sanitize_input(text):
    if not text:
        return text
    text = str(text)
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    text = text.replace('"', '&quot;').replace("'", '&#x27;')
    text = text.replace('&', '&amp;').replace('/', '&#x2F;')
    return text

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_UPLOAD_EXTENSIONS

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            full_name = request.form.get('full_name', '').strip()
            
            if not username or not email or not password or not confirm_password:
                flash('All fields are required.', 'danger')
                return render_template('register.html')
            
            if len(username) > MAX_INPUT_LENGTH or len(email) > MAX_INPUT_LENGTH or len(full_name) > MAX_INPUT_LENGTH:
                flash('Input exceeds maximum length.', 'danger')
                log_activity(None, 'registration_input_length_violation', request.remote_addr, f'Username: {username[:50]}')
                return render_template('register.html')
            
            username = sanitize_input(username)
            email = sanitize_input(email)
            full_name = sanitize_input(full_name)
            
            if not validate_email(email):
                flash('Invalid email format.', 'danger')
                return render_template('register.html')
            
            is_strong, message = validate_password_strength(password)
            if not is_strong:
                flash(message, 'danger')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('register.html')
            
            conn = get_db()
            existing = conn.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
            if existing:
                flash('Username or email already exists.', 'danger')
                log_activity(None, 'duplicate_registration_attempt', request.remote_addr, f'Username: {username}')
                conn.close()
                return render_template('register.html')
            
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            conn.execute(
                'INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, full_name)
            )
            conn.commit()
            
            user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            log_activity(user['id'], 'user_registered', request.remote_addr, f'User {username} registered')
            conn.close()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'danger')
            log_activity(None, 'registration_error', request.remote_addr, str(e)[:200])
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Username and password are required.', 'danger')
                return render_template('login.html')
            
            username = sanitize_input(username)
            
            conn = get_db()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            
            if not user:
                flash('Invalid username or password.', 'danger')
                log_activity(None, 'login_failed_invalid_user', request.remote_addr, f'Username: {username}')
                conn.close()
                return render_template('login.html')
            
            if user['account_locked'] == 1:
                flash('Account is locked due to multiple failed login attempts. Please contact support.', 'danger')
                log_activity(user['id'], 'login_attempt_locked_account', request.remote_addr, f'Username: {username}')
                conn.close()
                return render_template('login.html')
            
            if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                conn.execute('UPDATE users SET failed_login_attempts = 0 WHERE id = ?', (user['id'],))
                conn.commit()
                
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                log_activity(user['id'], 'user_logged_in', request.remote_addr, f'User {username} logged in')
                conn.close()
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                failed_attempts = user['failed_login_attempts'] + 1
                if failed_attempts >= 5:
                    conn.execute('UPDATE users SET failed_login_attempts = ?, account_locked = 1 WHERE id = ?', 
                               (failed_attempts, user['id']))
                    conn.commit()
                    flash('Account locked due to multiple failed login attempts.', 'danger')
                    log_activity(user['id'], 'account_locked', request.remote_addr, f'Username: {username}')
                else:
                    conn.execute('UPDATE users SET failed_login_attempts = ? WHERE id = ?', (failed_attempts, user['id']))
                    conn.commit()
                    flash(f'Invalid username or password. Attempts remaining: {5 - failed_attempts}', 'danger')
                    log_activity(user['id'], 'login_failed_wrong_password', request.remote_addr, f'Username: {username}')
                
                conn.close()
                return render_template('login.html')
                
        except Exception as e:
            flash('An error occurred. Please try again.', 'danger')
            log_activity(None, 'login_error', request.remote_addr, str(e)[:200])
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    log_activity(user_id, 'user_logged_out', request.remote_addr, f'User {username} logged out')
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    transactions = conn.execute(
        'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    
    return render_template('dashboard.html', user=user, transactions=transactions)

@app.route('/security-testing')
def security_testing():
    return render_template('security_testing.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip()
            
            if not full_name or not email:
                flash('All fields are required.', 'danger')
                return redirect(url_for('profile'))
            
            if len(full_name) > MAX_INPUT_LENGTH or len(email) > MAX_INPUT_LENGTH:
                flash('Input exceeds maximum length.', 'danger')
                return redirect(url_for('profile'))
            
            full_name = sanitize_input(full_name)
            email = sanitize_input(email)
            
            if not validate_email(email):
                flash('Invalid email format.', 'danger')
                return redirect(url_for('profile'))
            
            conn = get_db()
            existing = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?', 
                                  (email, session['user_id'])).fetchone()
            if existing:
                flash('Email already in use by another account.', 'danger')
                conn.close()
                return redirect(url_for('profile'))
            
            conn.execute('UPDATE users SET full_name = ?, email = ? WHERE id = ?',
                       (full_name, email, session['user_id']))
            conn.commit()
            
            log_activity(session['user_id'], 'profile_updated', request.remote_addr, 
                       f'Updated profile for user {session["username"]}')
            conn.close()
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            flash('An error occurred while updating profile.', 'danger')
            log_activity(session['user_id'], 'profile_update_error', request.remote_addr, str(e)[:200])
            return redirect(url_for('profile'))
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/add_transaction', methods=['POST'])
@login_required
def add_transaction():
    try:
        transaction_type = request.form.get('transaction_type', '').strip()
        amount_str = request.form.get('amount', '').strip()
        description = request.form.get('description', '').strip()
        
        if not transaction_type or not amount_str:
            flash('Transaction type and amount are required.', 'danger')
            return redirect(url_for('dashboard'))
        
        if not re.match(r'^\d+(\.\d{1,2})?$', amount_str):
            flash('Invalid amount format. Please enter a valid number.', 'danger')
            log_activity(session['user_id'], 'invalid_amount_format', request.remote_addr, f'Amount: {amount_str}')
            return redirect(url_for('dashboard'))
        
        amount = float(amount_str)
        description = sanitize_input(description)
        
        encrypted_desc = encrypt_data(description) if description else None
        
        conn = get_db()
        conn.execute(
            'INSERT INTO transactions (user_id, transaction_type, amount, description, encrypted_data) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], transaction_type, amount, description, encrypted_desc)
        )
        
        if transaction_type == 'deposit':
            conn.execute('UPDATE users SET account_balance = account_balance + ? WHERE id = ?',
                       (amount, session['user_id']))
        elif transaction_type == 'withdrawal':
            conn.execute('UPDATE users SET account_balance = account_balance - ? WHERE id = ?',
                       (amount, session['user_id']))
        
        conn.commit()
        
        log_activity(session['user_id'], 'transaction_added', request.remote_addr,
                   f'Type: {transaction_type}, Amount: {amount}')
        conn.close()
        
        flash('Transaction added successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    except ValueError:
        flash('Invalid amount. Please enter a valid number.', 'danger')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An error occurred while adding transaction.', 'danger')
        log_activity(session['user_id'], 'transaction_error', request.remote_addr, str(e)[:200])
        return redirect(url_for('dashboard'))

@app.route('/upload_document', methods=['POST'])
@login_required
def upload_document():
    try:
        if 'document' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(url_for('dashboard'))
        
        file = request.files['document']
        
        if not file.filename or file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('dashboard'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{session['user_id']}_{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            file.save(filepath)
            
            log_activity(session['user_id'], 'document_uploaded', request.remote_addr,
                       f'Filename: {filename}, Saved as: {unique_filename}')
            
            flash(f'File {filename} uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type. Allowed types: txt, pdf, png, jpg, jpeg, gif', 'danger')
            log_activity(session['user_id'], 'invalid_file_upload_attempt', request.remote_addr,
                       f'Filename: {file.filename}')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        flash('An error occurred during file upload.', 'danger')
        log_activity(session['user_id'], 'file_upload_error', request.remote_addr, str(e)[:200])
        return redirect(url_for('dashboard'))

@app.route('/test_error')
@login_required
def test_error():
    try:
        result = 10 / 0
        return str(result)
    except ZeroDivisionError:
        flash('An error occurred while processing your request.', 'danger')
        log_activity(session['user_id'], 'controlled_error_test', request.remote_addr, 'Divide by zero test')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('An unexpected error occurred.', 'danger')
        return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    log_activity(session.get('user_id'), 'server_error', request.remote_addr, str(e)[:200])
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
