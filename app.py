from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import re
import html
import hashlib
import secrets
import base64
from datetime import datetime
import os
import platform

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # For flash messages

# Common weak passwords list
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "admin",
    "letmein", "welcome", "monkey", "dragon", "abc123",
    "12345678", "iloveyou", "sunshine", "princess", "football"
}

# Dictionary words list
DICTIONARY_WORDS = {
    "apple", "computer", "dragon", "monkey", "password", "welcome",
    "admin", "user", "login", "letmein", "sunshine", "shadow",
    "master", "baseball", "football", "qwerty", "abc123"
}

# Downloads folder path
DOWNLOADS_PATH = os.path.join(os.path.expanduser("~"), "Downloads")
OUTPUT_FILE = os.path.join(DOWNLOADS_PATH, "passwords.txt")

# ============================================================================
# MAIN ROUTES
# ============================================================================

@app.route('/')
def index():
    """Main menu page"""
    return render_template('index.html')

@app.route('/password-strength', methods=['GET', 'POST'])
def password_strength():
    """Password Strength Analyzer"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        if not password.strip():
            flash('Please enter a password to analyze', 'warning')
            return render_template('password_strength.html')
        
        # Evaluate password strength
        results = evaluate_password_strength(password)
        return render_template('password_strength.html', results=results, password=password)
    
    return render_template('password_strength.html')

@app.route('/password-hasher', methods=['GET', 'POST'])
def password_hasher():
    """Password Hasher & Storage"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'generate':
            # Generate secure password
            password = generate_secure_password()
            return jsonify({'password': password})
        
        elif action == 'save':
            password = request.form.get('password', '')
            
            if not password.strip():
                flash('Please generate or enter a password first', 'warning')
                return redirect(url_for('password_hasher'))
            
            # Save password entry
            try:
                timestamp, password_hash = save_password_entry(password)
                flash(f'✅ Password saved successfully! Hash: {password_hash[:32]}...', 'success')
            except Exception as e:
                flash(f'❌ Error saving password: {str(e)}', 'danger')
            
            return redirect(url_for('password_hasher'))
    
    return render_template('password_hasher.html')

@app.route('/web-form-validator', methods=['GET', 'POST'])
def web_form_validator():
    """Web Form Validator & Sanitizer"""
    if request.method == 'POST':
        form_data = {
            'full_name': request.form.get('full_name', '').strip(),
            'email': request.form.get('email', '').strip(),
            'username': request.form.get('username', '').strip(),
            'message': request.form.get('message', '').strip()
        }
        
        # Validate form
        results = validate_web_form(form_data)
        
        if results.get('has_errors'):
            flash('Please fill in all required fields', 'danger')
            return render_template('web_form_validator.html', form_data=form_data, results=results)
        
        return render_template('web_form_validator.html', form_data=form_data, results=results)
    
    return render_template('web_form_validator.html')

# ============================================================================
# SECURITY FUNCTIONS (from your original code)
# ============================================================================

def evaluate_password_strength(password):
    """Evaluate password against all 7 criteria"""
    results = {
        'criteria': [],
        'passed_count': 0,
        'rating': '',
        'color': '',
        'advice': []
    }
    
    # CRITERION 1: Minimum Length
    meets_length = len(password) >= 12
    results['criteria'].append({
        'name': 'Minimum 12 characters',
        'passed': meets_length,
        'message': f"Minimum 12 characters (currently {len(password)})" if not meets_length else "Minimum 12 characters"
    })
    if meets_length:
        results['passed_count'] += 1
    
    # CRITERION 2: Uppercase letter
    has_upper = bool(re.search(r'[A-Z]', password))
    results['criteria'].append({
        'name': 'Contains uppercase letter (A-Z)',
        'passed': has_upper,
        'message': 'Contains uppercase letter (A-Z)' if has_upper else 'Missing uppercase letter (A-Z)'
    })
    if has_upper:
        results['passed_count'] += 1
    
    # CRITERION 3: Lowercase letter
    has_lower = bool(re.search(r'[a-z]', password))
    results['criteria'].append({
        'name': 'Contains lowercase letter (a-z)',
        'passed': has_lower,
        'message': 'Contains lowercase letter (a-z)' if has_lower else 'Missing lowercase letter (a-z)'
    })
    if has_lower:
        results['passed_count'] += 1
    
    # CRITERION 4: Number
    has_digit = bool(re.search(r'\d', password))
    results['criteria'].append({
        'name': 'Contains number (0-9)',
        'passed': has_digit,
        'message': 'Contains number (0-9)' if has_digit else 'Missing number (0-9)'
    })
    if has_digit:
        results['passed_count'] += 1
    
    # CRITERION 5: Special character
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]', password))
    results['criteria'].append({
        'name': 'Contains special character (!@#$%^&* etc.)',
        'passed': has_special,
        'message': 'Contains special character (!@#$%^&* etc.)' if has_special else 'Missing special character (!@#$%^&* etc.)'
    })
    if has_special:
        results['passed_count'] += 1
    
    # CRITERION 6: Not a common password
    is_common = password.lower() in COMMON_PASSWORDS
    results['criteria'].append({
        'name': 'Not a common password',
        'passed': not is_common,
        'message': 'DANGEROUS: Common password (easily guessed)' if is_common else 'Not a common password'
    })
    if not is_common:
        results['passed_count'] += 1
    
    # CRITERION 7: Not a dictionary word
    contains_dict_word = contains_dictionary_word(password)
    results['criteria'].append({
        'name': 'No dictionary words detected',
        'passed': not contains_dict_word,
        'message': 'Contains dictionary word (predictable)' if contains_dict_word else 'No dictionary words detected'
    })
    if not contains_dict_word:
        results['passed_count'] += 1
    
    # DETERMINE FINAL RATING
    is_weak = (results['passed_count'] < 4) or is_common or contains_dict_word
    
    if is_weak:
        results['rating'] = 'WEAK'
        results['color'] = 'danger'
        results['advice'] = [
            "⚠️ This password is vulnerable to brute-force attacks.",
            "Recommendations:",
            "• Increase length to 12+ characters",
            "• Add uppercase, numbers, and symbols",
            "• Avoid dictionary words and common patterns"
        ]
    elif results['passed_count'] >= 6:
        results['rating'] = 'STRONG'
        results['color'] = 'success'
        results['advice'] = [
            "✅ Excellent password strength!",
            "Recommendations:",
            "• Use a unique password for each account",
            "• Consider a password manager for storage",
            "• Change periodically (every 90 days)"
        ]
    else:
        results['rating'] = 'MODERATE'
        results['color'] = 'warning'
        results['advice'] = [
            "⚠️ Acceptable but could be stronger.",
            "Recommendations:",
            "• Add special characters (!@#$%)",
            "• Increase length beyond 12 characters",
            "• Avoid predictable substitutions (e.g., 'P@ssw0rd')"
        ]
    
    return results

def contains_dictionary_word(password):
    """Check if password contains dictionary words"""
    pwd_lower = password.lower()
    normalized = pwd_lower.replace("0", "o").replace("1", "i").replace("3", "e")
    normalized = normalized.replace("4", "a").replace("5", "s").replace("@", "a")
    normalized = normalized.replace("$", "s").replace("!", "i")
    
    for word in DICTIONARY_WORDS:
        if word in pwd_lower or word in normalized:
            return True
    return False

def generate_secure_password():
    """Generate cryptographically strong password"""
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    all_chars = uppercase + lowercase + digits + special
    password += [secrets.choice(all_chars) for _ in range(12)]
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def save_password_entry(password):
    """Save password entry to file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    salt = secrets.token_bytes(32)
    salted_password = salt + password.encode('utf-8')
    password_hash = hashlib.sha256(salted_password).hexdigest()
    
    entry = (
        f"Timestamp: {timestamp}\n"
        f"Password: {password}\n"
        f"Hash: {password_hash}\n"
        f"{'='*60}\n"
    )
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
        f.write(entry)
    
    return timestamp, password_hash

def validate_web_form(form_data):
    """Validate web form inputs"""
    results = {
        'validation': {},
        'sanitization': {},
        'final_output': {},
        'sanitized_count': 0,
        'has_errors': False
    }
    
    # Check for empty fields
    for field_name, value in form_data.items():
        if not value:
            results['has_errors'] = True
            results['validation'][field_name] = {
                'valid': False,
                'message': f"{field_name.replace('_', ' ').title()} cannot be empty"
            }
    
    if results['has_errors']:
        return results
    
    # Validate each field
    # Full Name
    is_valid, message = validate_full_name(form_data['full_name'])
    results['validation']['full_name'] = {'valid': is_valid, 'message': message}
    if not is_valid:
        sanitized = sanitize_full_name(form_data['full_name'])
        results['sanitization']['full_name'] = {'value': sanitized, 'changed': sanitized != form_data['full_name']}
        results['final_output']['full_name'] = sanitized
        if sanitized != form_data['full_name']:
            results['sanitized_count'] += 1
    else:
        results['final_output']['full_name'] = form_data['full_name']
    
    # Email
    is_valid, message = validate_email(form_data['email'])
    results['validation']['email'] = {'valid': is_valid, 'message': message}
    if not is_valid:
        sanitized = sanitize_email(form_data['email'])
        results['sanitization']['email'] = {'value': sanitized, 'changed': sanitized != form_data['email']}
        results['final_output']['email'] = sanitized
        if sanitized != form_data['email']:
            results['sanitized_count'] += 1
    else:
        results['final_output']['email'] = form_data['email']
    
    # Username
    is_valid, message = validate_username(form_data['username'])
    results['validation']['username'] = {'valid': is_valid, 'message': message}
    if not is_valid:
        sanitized = sanitize_username(form_data['username'])
        results['sanitization']['username'] = {'value': sanitized, 'changed': sanitized != form_data['username']}
        results['final_output']['username'] = sanitized
        if sanitized != form_data['username']:
            results['sanitized_count'] += 1
    else:
        results['final_output']['username'] = form_data['username']
    
    # Message
    is_valid, message, threats = validate_message(form_data['message'])
    results['validation']['message'] = {'valid': is_valid, 'message': message, 'threats': threats}
    if not is_valid:
        sanitized = sanitize_message(form_data['message'])
        results['sanitization']['message'] = {'value': sanitized, 'changed': sanitized != form_data['message']}
        results['final_output']['message'] = sanitized
        if sanitized != form_data['message']:
            results['sanitized_count'] += 1
    else:
        results['final_output']['message'] = form_data['message']
    
    return results

# Validation functions (same as your original code)
def validate_full_name(name):
    if not name or not name.strip():
        return False, "Full Name cannot be empty"
    name = name.strip()
    if len(name) < 2:
        return False, "Must be at least 2 characters long"
    if re.search(r'\d', name):
        return False, "Must not contain numbers"
    if not re.match(r'^[a-zA-Z\s\'\-]+$', name):
        return False, "Must not contain special characters except spaces, hyphens, or apostrophes"
    return True, "Valid"

def validate_email(email):
    if not email or not email.strip():
        return False, "Email Address cannot be empty"
    email = email.strip()
    if ' ' in email:
        return False, "Must not contain spaces"
    if email and not email[0].isalnum():
        return False, "Cannot start with a special character"
    if '@' not in email:
        return False, "Must contain an '@' symbol"
    if email.count('@') != 1:
        return False, "Must contain exactly one '@' symbol"
    try:
        local_part, domain_part = email.split('@')
    except ValueError:
        return False, "Format is invalid"
    if not local_part:
        return False, "Local part cannot be empty"
    if '.' not in domain_part:
        return False, "Must contain a domain name (e.g., .com, .org)"
    tld = domain_part.split('.')[-1]
    if len(tld) < 2:
        return False, "Must have a valid top-level domain (e.g., .com, .org)"
    return True, "Valid"

def validate_username(username):
    if not username or not username.strip():
        return False, "Username cannot be empty"
    username = username.strip()
    if len(username) < 4:
        return False, "Must be at least 4 characters long"
    if len(username) > 16:
        return False, "Must not exceed 16 characters"
    if username[0].isdigit():
        return False, "Cannot begin with a number"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Can only contain letters, numbers, and underscores"
    return True, "Valid"

def validate_message(message):
    if not message or not message.strip():
        return False, "Message cannot be empty", []
    message = message.strip()
    if len(message) > 250:
        return False, f"Must not exceed 250 characters (current: {len(message)})", []
    threats = []
    if re.search(r'<script.*?>', message, re.IGNORECASE):
        threats.append("script tag")
    if re.search(r'<img[^>]*on\w+\s*=', message, re.IGNORECASE):
        threats.append("img tag with event handler")
    sql_keywords = ['SELECT', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 'UNION', 'EXEC']
    for keyword in sql_keywords:
        if re.search(r'\b' + keyword + r'\b', message, re.IGNORECASE):
            threats.append(f"SQL keyword '{keyword}'")
            break
    if threats:
        threat_list = ", ".join(threats)
        return False, f"Contains prohibited patterns: {threat_list}", threats
    return True, "Valid", []

# Sanitization functions
def sanitize_full_name(name):
    if not name:
        return ""
    return re.sub(r'[^a-zA-Z\s\'\-]', '', name).strip()

def sanitize_email(email):
    if not email:
        return ""
    return email.replace(' ', '').strip()

def sanitize_username(username):
    if not username:
        return ""
    return re.sub(r'[^a-zA-Z0-9_]', '', username).strip()

def sanitize_message(message):
    if not message:
        return ""
    return html.escape(message, quote=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)