import sqlite3
import re
from cryptography.fernet import Fernet
import os

def get_or_create_encryption_key():
    key_file = '.encryption_key'
    env_key = os.environ.get('ENCRYPTION_KEY')
    
    if env_key:
        return env_key.encode() if isinstance(env_key, str) else env_key
    
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    
    new_key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(new_key)
    
    return new_key

ENCRYPTION_KEY = get_or_create_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    if not data:
        return None
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    if not encrypted_data:
        return None
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except:
        return None

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_strength(password):
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long.'
    
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter.'
    
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter.'
    
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one digit.'
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, 'Password must contain at least one special character.'
    
    return True, 'Password is strong.'

def log_activity(user_id, action, ip_address, details=''):
    try:
        conn = sqlite3.connect('fintech.db')
        conn.execute(
            'INSERT INTO audit_logs (user_id, action, ip_address, details) VALUES (?, ?, ?, ?)',
            (user_id, action, ip_address, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f'Logging error: {e}')
