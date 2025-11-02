# 🍌 Minions FinTech - Secure Banking Application

A comprehensive FinTech security demonstration application with **22 manual cybersecurity test cases** for academic security assessment.

![Minions Theme](https://img.shields.io/badge/Theme-Minions-yellow?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Excellent-green?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-3.1.2-black?style=for-the-badge)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Security Features](#security-features)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Security Test Cases](#security-test-cases)
- [Screenshots](#screenshots)
- [License](#license)

---

## 🎯 Overview

Minions FinTech is a secure web application built with Python Flask that demonstrates comprehensive cybersecurity concepts including:

- ✅ Secure user authentication and authorization
- ✅ Input validation and sanitization
- ✅ Data encryption and protection
- ✅ Session management
- ✅ Secure error handling
- ✅ Audit logging
- ✅ File upload validation
- ✅ Protection against OWASP Top 10 vulnerabilities

The application features an attractive **Minions theme** with yellow and blue colors, complete with Minions logo branding for an engaging user experience.

---

## ✨ Features

### User Management
- **Secure Registration**: Email validation, strong password enforcement, duplicate prevention
- **Secure Login**: Bcrypt password hashing, rate limiting, account lockout after 5 failed attempts
- **Profile Management**: Update personal information with validation
- **Session Management**: Automatic timeout after 5 minutes of inactivity

### Financial Operations
- **Account Balance Tracking**: Real-time balance updates
- **Transaction Management**: Add deposits and withdrawals
- **Transaction History**: View recent transactions with encryption
- **Data Encryption**: Sensitive data encrypted using Fernet encryption

### Security Features
- **SQL Injection Prevention**: Parameterized queries and input sanitization
- **XSS Protection**: Input sanitization and output escaping
- **CSRF Protection**: Session-based protection
- **File Upload Validation**: Whitelist-based file type checking
- **Secure Headers**: X-Frame-Options, CSP, HSTS, X-XSS-Protection
- **Audit Logging**: Comprehensive activity tracking

---

## 🔐 Security Features

### Authentication & Authorization
- ✅ Bcrypt password hashing with salt (12 rounds)
- ✅ Strong password policy (8+ chars, uppercase, lowercase, digit, special character)
- ✅ Session-based authentication with secure cookies
- ✅ Login attempt limiting (5 attempts before lockout)
- ✅ Automatic session timeout (5 minutes)

### Input Validation & Sanitization
- ✅ XSS prevention through HTML escaping
- ✅ SQL injection prevention (parameterized queries)
- ✅ Email format validation (regex)
- ✅ Input length validation (max 1000 characters)
- ✅ Number field validation with regex patterns
- ✅ Unicode/emoji handling

### Data Protection
- ✅ Password hashing with bcrypt
- ✅ Fernet encryption for sensitive data
- ✅ Encrypted transaction descriptions
- ✅ Secure database storage

### Session Management
- ✅ Secure session secret keys
- ✅ Automatic session expiry
- ✅ Proper session clearing on logout
- ✅ Session hijacking prevention

### Error Handling
- ✅ Generic error messages (no information leakage)
- ✅ Controlled exception handling
- ✅ No stack trace exposure
- ✅ Comprehensive error logging

### Security Headers
- ✅ X-Frame-Options: DENY (clickjacking protection)
- ✅ X-Content-Type-Options: nosniff
- ✅ X-XSS-Protection: 1; mode=block
- ✅ Content-Security-Policy
- ✅ Strict-Transport-Security (HSTS)
- ✅ Cache-Control: no-cache (prevents sensitive data caching)

### File Upload Security
- ✅ File type validation (whitelist: txt, pdf, png, jpg, jpeg, gif)
- ✅ File size limits (16MB max)
- ✅ Secure filename handling with Werkzeug

### Audit Logging
- ✅ User registration/login tracking
- ✅ Failed login attempt logging
- ✅ Transaction logging
- ✅ Profile update tracking
- ✅ IP address logging
- ✅ Security event logging

---

## 📦 Installation

### Prerequisites

- Python 3.11 or higher
- pip (Python package manager)
- Git

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd minions-fintech
```

### Step 2: Install Dependencies

All required packages are listed in the project and will be installed automatically on Replit. For local installation:

```bash
pip install flask bcrypt cryptography python-dotenv flask-limiter werkzeug
```

### Step 3: Set Environment Variables (Optional)

Create a `.env` file for custom configuration:

```bash
SESSION_SECRET=your-secret-key-here
ENCRYPTION_KEY=your-encryption-key-here
```

If not provided, secure random keys will be generated automatically.

### Step 4: Initialize the Database

The database will be automatically created when you first run the application.

### Step 5: Run the Application

```bash
python app.py
```

The application will be available at: `http://localhost:5000`

---

## 🚀 Usage

### 1. Register a New Account

- Navigate to the registration page
- Fill in your details (username, email, full name, password)
- Password must meet strength requirements:
  - At least 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
  - At least one special character

### 2. Login

- Use your username and password to login
- Account will lock after 5 failed login attempts

### 3. Dashboard

- View your account balance
- Add transactions (deposits/withdrawals)
- Upload documents (txt, pdf, images)
- View recent transaction history

### 4. Profile Management

- Update your full name
- Change your email address
- View account information

### 5. Logout

- Click the logout button to securely end your session
- Session data will be completely cleared

---

## 🧪 Testing

### Running Security Tests

All 22 security test cases have been documented in `SECURITY_TEST_DOCUMENTATION.md`. 

### Test Categories

1. **Input Validation Tests** (Cases 1, 3, 10, 12, 15, 19, 20)
2. **Authentication Tests** (Cases 2, 4, 6, 13, 16)
3. **Session Management Tests** (Cases 5, 6, 21)
4. **Data Protection Tests** (Cases 7, 18)
5. **File Security Tests** (Case 8)
6. **Error Handling Tests** (Cases 9, 17)
7. **Authorization Tests** (Cases 4, 14)
8. **Security Headers Tests** (Case 22)

### How to Test

Each test case in the documentation includes:
- Test case number and name
- Action to perform
- Expected outcome
- Observed result
- Pass/Fail status

Follow the instructions in `SECURITY_TEST_DOCUMENTATION.md` to replicate all 22 tests.

---

## 📁 Project Structure

```
minions-fintech/
│
├── app.py                              # Main Flask application
├── utils.py                            # Utility functions (encryption, validation, logging)
├── fintech.db                          # SQLite database (auto-created)
│
├── templates/                          # HTML templates
│   ├── base.html                       # Base template with Minions theme
│   ├── login.html                      # Login page
│   ├── register.html                   # Registration page
│   ├── dashboard.html                  # Main dashboard
│   ├── profile.html                    # User profile page
│   ├── 404.html                        # 404 error page
│   └── 500.html                        # 500 error page
│
├── static/                             # Static files
│   └── css/
│       └── style.css                   # Minions-themed CSS
│
├── uploads/                            # File upload directory
│
├── README.md                           # This file
├── SECURITY_TEST_DOCUMENTATION.md      # Complete test documentation
└── .gitignore                          # Git ignore file
```

---

## 🛠 Technologies Used

### Backend
- **Python 3.11**: Programming language
- **Flask 3.1.2**: Web framework
- **SQLite**: Database
- **bcrypt**: Password hashing
- **cryptography (Fernet)**: Data encryption
- **Werkzeug**: Security utilities
- **Flask-Limiter**: Rate limiting

### Frontend
- **HTML5**: Structure
- **CSS3**: Styling (Minions theme)
- **JavaScript**: Form validation
- **Google Fonts**: Bangers & Quicksand fonts

### Security Libraries
- **bcrypt**: Password hashing
- **cryptography**: Fernet encryption
- **Werkzeug.security**: Secure filename handling
- **Flask sessions**: Session management

---

## 🔍 Security Test Cases

All **22 test cases** have been executed and **PASSED**:

### Input Validation (7 tests)
1. ✅ SQL Injection Prevention
2. ✅ XSS Attack Prevention
3. ✅ Input Length Validation
4. ✅ Number Field Validation
5. ✅ Email Format Validation
6. ✅ Unicode/Emoji Handling
7. ✅ Empty Field Submission

### Authentication & Authorization (6 tests)
8. ✅ Password Strength Validation
9. ✅ Unauthorized Dashboard Access
10. ✅ Logout Functionality
11. ✅ Password Match Verification
12. ✅ Login Attempt Lockout
13. ✅ Data Modification Prevention

### Data Protection (2 tests)
14. ✅ Data Confidentiality (Hashed Passwords)
15. ✅ Encrypted Record Check

### Session Management (2 tests)
16. ✅ Session Expiry
17. ✅ CSRF Token Validation

### File Security (1 test)
18. ✅ File Upload Validation

### Error Handling (2 tests)
19. ✅ Error Message Leakage Prevention
20. ✅ Secure Error Handling

### Infrastructure (2 tests)
21. ✅ Duplicate User Registration
22. ✅ Secure Headers Implementation

**Overall Test Success Rate**: 100% (22/22 PASSED)

For detailed test results, see `SECURITY_TEST_DOCUMENTATION.md`

---

## 📸 Screenshots

### Login Page
Minions-themed login interface with secure authentication

### Dashboard
Interactive dashboard with account balance, transaction management, and file uploads

### Profile Page
User profile management with validation

### Registration
Secure registration with strong password enforcement

---

## 🎨 Minions Theme

The application features a vibrant Minions theme:

- **Colors**: Yellow (#FFD700), Blue (#1E90FF), Dark Blue (#0066CC)
- **Fonts**: Bangers (headings), Quicksand (body)
- **Elements**: Minions eyes logo, banana emoji, playful messaging
- **Responsive**: Mobile-friendly design

---

## 🔒 OWASP Top 10 Coverage

This application addresses all OWASP Top 10 vulnerabilities:

1. ✅ **Injection** - Parameterized queries, input sanitization
2. ✅ **Broken Authentication** - Bcrypt, session management, lockout
3. ✅ **Sensitive Data Exposure** - Encryption, secure storage
4. ✅ **XML External Entities** - Not applicable (no XML)
5. ✅ **Broken Access Control** - Login decorators, session checks
6. ✅ **Security Misconfiguration** - Security headers, secure defaults
7. ✅ **Cross-Site Scripting** - Input sanitization, output escaping
8. ✅ **Insecure Deserialization** - Not applicable
9. ✅ **Using Components with Known Vulnerabilities** - Latest packages
10. ✅ **Insufficient Logging** - Comprehensive audit logging

---

## 📚 Documentation

- **README.md** - Setup and usage instructions (this file)
- **SECURITY_TEST_DOCUMENTATION.md** - Complete security testing documentation with all 22 test cases

---

## 🤝 Contributing

This is an academic project for security assessment. For questions or suggestions, please contact the project maintainer.

---

## 📝 License

This project is created for educational purposes as part of a cybersecurity course assignment.

---

## 👨‍💻 Author

Created for academic cybersecurity assessment - Fall 2024

---

## 🍌 Bello!

Thank you for using Minions FinTech! Stay secure and keep your bananas safe! 🍌

---

*Last Updated: November 2024*
