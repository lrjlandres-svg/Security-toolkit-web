# MO-IT142 Security Toolkit - Web Application

## Project Overview

This is a **web-based security toolkit** developed for MO-IT142 Security Script Programming course. The application provides three integrated security tools for password analysis, hashing, and web form validation.

### Important Note

This submission addresses the mentor's feedback regarding the **web application requirement** for Milestone 1. The original Tkinter desktop application has been converted to a Flask web application to meet the course requirements.

---

## Features

### 1. Password Strength Analyzer
- Evaluates passwords against 7 security criteria
- Detects common passwords and dictionary words
- Provides detailed security recommendations
- Real-time strength visualization

### 2. Password Hasher & Storage
- Generates cryptographically secure passwords
- SHA-256 hashing with 256-bit salt
- Saves entries to `passwords.txt` in Downloads folder
- Append mode (never overwrites existing data)

### 3. Web Form Validator & Sanitizer
- Validates Full Name, Email, Username, and Message fields
- Detects XSS and SQL injection patterns
- Sanitizes dangerous HTML/SQL content
- Real-time validation feedback

---

## Technology Stack

- **Backend**: Python 3.8+, Flask 2.3+
- **Frontend**: HTML5, CSS3, Bootstrap 5.3
- **Security Libraries**: 
  - `hashlib` - Password hashing
  - `secrets` - Cryptographic random generation
  - `re` - Pattern matching and validation
  - `html` - HTML sanitization

---

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation Steps

1. **Clone or download the project**
   ```bash
   git clone https://github.com/lrjlandres-svg/Security-toolkit-web.git
   cd security_toolkit_web

   
   ---
   
 ### Usage Guide
### Password Strength Analyzer
- Navigate to "Password Strength" from the menu
- Enter a password in the input field
- Click "Analyze Password Strength"
- Review the detailed security analysis and recommendations
### Password Hasher & Storage
- Navigate to "Password Hasher" from the menu
- Click "Generate Secure Password" or enter your own
- Click "Save Password Entry"
- View confirmation with timestamp and hash
### Web Form Validator
- Navigate to "Form Validator" from the menu
- Fill in all form fields (Full Name, Email, Username, Message)
- Click "Validate Form"
- Review validation results and sanitized output
