from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import sqlite3
import json
import re
import urllib.request
import urllib.parse
import ssl
import hashlib
import secrets
from datetime import datetime
from functools import wraps



app = Flask(__name__, template_folder='.', static_folder='.')
app.secret_key = secrets.token_hex(32)
CORS(app)
bcrypt = Bcrypt(app)

DATABASE = 'vulnscan.db'

# Database Setup
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT DEFAULT 'completed',
            vulnerabilities TEXT,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Auth Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Vulnerability Detection Engine
class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []
        self.headers = {}
        
    def scan(self, scan_type='quick'):
        """Run vulnerability scan"""
        try:
            # Fetch the target URL
            self._fetch_url()
            
            # Run checks
            self._check_security_headers()
            self._check_sql_injection()
            self._check_xss()
            self._check_csrf()
            self._check_information_disclosure()
            
            if scan_type == 'full':
                self._check_advanced_headers()
                self._check_cookie_security()
                
        except Exception as e:
            self.vulnerabilities.append({
                'name': 'Scan Error',
                'severity': 'low',
                'description': f'Unable to complete scan: {str(e)}'
            })
        
        return self.vulnerabilities
    
    def _fetch_url(self):
        """Fetch URL and extract information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(
                self.url,
                headers={'User-Agent': 'VulnScan/1.0 Security Scanner'}
            )
            
            with urllib.request.urlopen(req, timeout=10, context=context) as response:
                self.html_content = response.read().decode('utf-8', errors='ignore')
                self.headers = dict(response.headers)
        except Exception as e:
            raise Exception(f"Could not fetch URL: {str(e)}")
    
    def _check_security_headers(self):
        """Check for missing security headers"""
        security_headers = {
            'X-Frame-Options': {
                'name': 'Missing X-Frame-Options',
                'severity': 'medium',
                'description': 'Clickjacking protection header not present. This could allow the page to be embedded in malicious iframes.'
            },
            'X-Content-Type-Options': {
                'name': 'Missing X-Content-Type-Options',
                'severity': 'low',
                'description': 'MIME type sniffing protection not enabled. This could allow XSS attacks through uploaded files.'
            },
            'Strict-Transport-Security': {
                'name': 'Missing HSTS Header',
                'severity': 'medium',
                'description': 'HTTP Strict Transport Security not enforced. Connection may be vulnerable to downgrade attacks.'
            },
            'Content-Security-Policy': {
                'name': 'Missing Content Security Policy',
                'severity': 'medium',
                'description': 'CSP header not configured. This reduces protection against XSS and data injection attacks.'
            },
            'X-XSS-Protection': {
                'name': 'Missing X-XSS-Protection',
                'severity': 'low',
                'description': 'XSS protection header not present. Browser-level XSS filtering may not be enabled.'
            }
        }
        
        for header, vuln in security_headers.items():
            if header not in self.headers:
                self.vulnerabilities.append({
                    'name': vuln['name'],
                    'severity': vuln['severity'],
                    'description': vuln['description']
                })
    
    def _check_sql_injection(self):
        """Check for potential SQL injection points"""
        form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]*)[^>]*method=["\']?([^"\'>\s]*)'
        forms = re.findall(form_pattern, self.html_content, re.IGNORECASE)
        
        input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]*)[^>]*'
        inputs = re.findall(input_pattern, self.html_content, re.IGNORECASE)
        
        if forms and inputs:
            self.vulnerabilities.append({
                'name': 'Potential SQL Injection',
                'severity': 'high',
                'description': f'Found {len(forms)} form(s) with {len(inputs)} input field(s) that may be vulnerable to SQL injection. Manual testing recommended.'
            })
    
    def _check_xss(self):
        """Check for potential XSS vulnerabilities"""
        script_pattern = r'<script[^>]*>.*?</script>'
        scripts = re.findall(script_pattern, self.html_content, re.IGNORECASE | re.DOTALL)
        
        event_handlers = ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus']
        found_handlers = []
        
        for handler in event_handlers:
            if handler in self.html_content.lower():
                found_handlers.append(handler)
        
        if found_handlers:
            self.vulnerabilities.append({
                'name': 'Potential XSS Vector',
                'severity': 'high',
                'description': f'Found event handlers ({", ".join(found_handlers)}) that could be exploited for cross-site scripting attacks.'
            })
    
    def _check_csrf(self):
        """Check for CSRF protection"""
        csrf_patterns = [
            r'csrf[_-]?token',
            r'csrf[_-]?field',
            r'_token',
            r'authenticity_token'
        ]
        
        has_csrf = False
        for pattern in csrf_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                has_csrf = True
                break
        
        form_pattern = r'<form[^>]*method=["\']?post["\']?[^>]*>'
        post_forms = re.findall(form_pattern, self.html_content, re.IGNORECASE)
        
        if post_forms and not has_csrf:
            self.vulnerabilities.append({
                'name': 'CSRF Vulnerability',
                'severity': 'medium',
                'description': f'Found {len(post_forms)} POST form(s) without CSRF token protection. This could allow cross-site request forgery attacks.'
            })
    
    def _check_information_disclosure(self):
        """Check for information disclosure"""
        sensitive_patterns = [
            (r'Server:\s*([^\r\n]+)', 'Server Version Disclosure'),
            (r'X-Powered-By:\s*([^\r\n]+)', 'Technology Stack Disclosure'),
            (r'PHPSESSID', 'PHP Session ID Exposed'),
            (r'<!--.*?-->', 'HTML Comments Present')
        ]
        
        for pattern, name in sensitive_patterns:
            if re.search(pattern, str(self.headers), re.IGNORECASE):
                self.vulnerabilities.append({
                    'name': name,
                    'severity': 'low',
                    'description': f'Sensitive information detected in server response headers. This could help attackers plan targeted attacks.'
                })
                break
    
    def _check_advanced_headers(self):
        """Additional header checks for full scan"""
        permissions_policy = 'Permissions-Policy'
        if permissions_policy not in self.headers:
            self.vulnerabilities.append({
                'name': 'Missing Permissions Policy',
                'severity': 'low',
                'description': 'Permissions-Policy header not set. Browser features cannot be restricted.'
            })
        
        referrer_policy = 'Referrer-Policy'
        if referrer_policy not in self.headers:
            self.vulnerabilities.append({
                'name': 'Missing Referrer Policy',
                'severity': 'low',
                'description': 'Referrer-Policy header not configured. May leak sensitive URL information.'
            })
    
    def _check_cookie_security(self):
        """Check cookie security attributes"""
        set_cookie = self.headers.get('Set-Cookie', '')
        
        if set_cookie:
            issues = []
            if 'HttpOnly' not in set_cookie:
                issues.append('HttpOnly')
            if 'Secure' not in set_cookie:
                issues.append('Secure')
            if 'SameSite' not in set_cookie:
                issues.append('SameSite')
            
            if issues:
                self.vulnerabilities.append({
                    'name': 'Insecure Cookie Configuration',
                    'severity': 'medium',
                    'description': f'Cookies missing security attributes: {", ".join(issues)}. This could lead to session hijacking.'
                })

# API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not all(k in data for k in ['name', 'email', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    name = data['name'].strip()
    email = data['email'].strip().lower()
    password = data['password']
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
            (name, email, password_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        session['user_id'] = user_id
        session['user_email'] = email
        session['user_name'] = name
        
        return jsonify({
            'message': 'Registration successful',
            'user': {'id': user_id, 'name': name, 'email': email}
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 409

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not all(k in data for k in ['email', 'password']):
        return jsonify({'error': 'Missing email or password'}), 400
    
    email = data['email'].strip().lower()
    password = data['password']
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user['name']
        
        return jsonify({
            'message': 'Login successful',
            'user': {'id': user['id'], 'name': user['name'], 'email': user['email']}
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    return jsonify({
        'user': {
            'id': session.get('user_id'),
            'name': session.get('user_name'),
            'email': session.get('user_email')
        }
    })

@app.route('/api/scan', methods=['POST'])
@login_required
def create_scan():
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url'].strip()
    scan_type = data.get('type', 'quick')
    
    # Validate URL
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    # Run vulnerability scan
    scanner = VulnerabilityScanner(url)
    vulnerabilities = scanner.scan(scan_type)
    
    # Count severities
    high_count = sum(1 for v in vulnerabilities if v['severity'] == 'high')
    medium_count = sum(1 for v in vulnerabilities if v['severity'] == 'medium')
    low_count = sum(1 for v in vulnerabilities if v['severity'] == 'low')
    
    # Save to database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (user_id, url, scan_type, vulnerabilities, high_count, medium_count, low_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        session['user_id'],
        url,
        scan_type,
        json.dumps(vulnerabilities),
        high_count,
        medium_count,
        low_count
    ))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    
    return jsonify({
        'id': scan_id,
        'url': url,
        'type': scan_type,
        'vulnerabilities': vulnerabilities,
        'summary': {
            'total': len(vulnerabilities),
            'high': high_count,
            'medium': medium_count,
            'low': low_count
        }
    })

@app.route('/api/scans', methods=['GET'])
@login_required
def get_scans():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, url, scan_type, status, high_count, medium_count, low_count, created_at
        FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
    ''', (session['user_id'],))
    scans = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'scans': [{
            'id': scan['id'],
            'url': scan['url'],
            'type': scan['scan_type'],
            'status': scan['status'],
            'high': scan['high_count'],
            'medium': scan['medium_count'],
            'low': scan['low_count'],
            'timestamp': scan['created_at']
        } for scan in scans]
    })

@app.route('/api/scans/<int:scan_id>', methods=['GET'])
@login_required
def get_scan_details(scan_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM scans WHERE id = ? AND user_id = ?
    ''', (scan_id, session['user_id']))
    scan = cursor.fetchone()
    conn.close()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'id': scan['id'],
        'url': scan['url'],
        'type': scan['scan_type'],
        'status': scan['status'],
        'vulnerabilities': json.loads(scan['vulnerabilities']) if scan['vulnerabilities'] else [],
        'summary': {
            'high': scan['high_count'],
            'medium': scan['medium_count'],
            'low': scan['low_count']
        },
        'timestamp': scan['created_at']
    })

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as total FROM scans WHERE user_id = ?', (session['user_id'],))
    total_scans = cursor.fetchone()['total']
    
    cursor.execute('''
        SELECT 
            SUM(high_count) as high,
            SUM(medium_count) as medium,
            SUM(low_count) as low
        FROM scans WHERE user_id = ?
    ''', (session['user_id'],))
    counts = cursor.fetchone()
    conn.close()
    
    return jsonify({
        'totalScans': total_scans,
        'vulnerabilities': {
            'total': (counts['high'] or 0) + (counts['medium'] or 0) + (counts['low'] or 0),
            'high': counts['high'] or 0,
            'medium': counts['medium'] or 0,
            'low': counts['low'] or 0
        }
    })

# Serve the main application
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("  VulnScan - Web Application Vulnerability Detection System")
    print("="*60)
    print("\n  Server running at: http://localhost:5000")
    print("  API endpoints:")
    print("    POST /api/auth/register  - Register new user")
    print("    POST /api/auth/login     - Login user")
    print("    POST /api/auth/logout    - Logout user")
    print("    POST /api/scan           - Start vulnerability scan")
    print("    GET  /api/scans          - Get scan history")
    print("    GET  /api/scans/<id>     - Get scan details")
    print("    GET  /api/stats          - Get statistics")
    print("\n" + "="*60 + "\n")
    app.run(host="0.0.0.0", port=10000)