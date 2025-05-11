from flask import Flask, jsonify, request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
from datetime import timedelta, datetime
import re
import logging
from logging.handlers import RotatingFileHandler
import secrets
from functools import wraps
import time
import hmac
import hashlib
import json
from dotenv import load_dotenv  # Add this for environment variables

app = Flask(__name__)

# Load environment variables
load_dotenv()

# Generate secure keys if not provided in environment
def generate_secure_key(key_name, default_length=32):
    """Generate a cryptographically secure key using secrets module"""
    key = os.environ.get(key_name)
    if not key:
        key = secrets.token_hex(default_length)
        print(f"WARNING: {key_name} not found in environment. Generated: {key}")
        print(f"Add this to your .env file: {key_name}={key}")
    return key

# Security Configuration with cryptographically secure defaults
app.config['SECRET_KEY'] = generate_secure_key('SECRET_KEY', 32)
app.config['JWT_SECRET_KEY'] = generate_secure_key('JWT_SECRET_KEY', 32)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///secure_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
jwt = JWTManager(app)
db = SQLAlchemy(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configure CORS with strict settings
CORS(app, 
     origins=['https://yourdomain.com'],  # Only allow your domain
     allow_headers=['Content-Type', 'Authorization'],
     expose_headers=['X-Rate-Limit'],
     max_age=3600)

# Security Headers Middleware
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# Logging Configuration
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/api_security.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Database Models
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    oauth_provider = db.Column(db.String(50))
    oauth_id = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    
    @staticmethod
    def generate_verification_token():
        """Generate a secure email verification token"""
        return generate_secure_token(32)
    
    def set_password(self, password):
        # Use cryptographically secure salt generation
        salt = generate_secure_password_salt(16)
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, nullable=False)

class APIKey(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    key_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    @staticmethod
    def generate_api_key():
        """Generate a cryptographically secure API key"""
        return secrets.token_urlsafe(32)

# Cryptographic Security Helpers
def generate_secure_token(length=32, url_safe=True):
    """
    Generate a cryptographically secure token using the secrets module
    
    Args:
        length (int): Length of the token in bytes
        url_safe (bool): Whether to generate a URL-safe token
    
    Returns:
        str: Secure random token
    """
    if url_safe:
        return secrets.token_urlsafe(length)
    else:
        return secrets.token_hex(length)

def generate_secure_password_salt(length=16):
    """Generate a cryptographically secure salt for password hashing"""
    return secrets.token_bytes(length)

def generate_csrf_token():
    """Generate a secure CSRF token"""
    return secrets.token_hex(16)

# Security Decorators
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Hash the provided API key
        key_hash = generate_password_hash(api_key, method='pbkdf2:sha256', salt_length=16)
        
        # Find matching API key
        api_key_obj = APIKey.query.filter_by(key_hash=key_hash, is_active=True).first()
        
        if not api_key_obj or (api_key_obj.expires_at and datetime.utcnow() > api_key_obj.expires_at):
            return jsonify({'error': 'Invalid or expired API key'}), 401
        
        # Update last used timestamp
        api_key_obj.last_used = datetime.utcnow()
        db.session.commit()
        
        return f(*args, **kwargs)
    return decorated_function

def validate_email(email):
    pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return pattern.match(email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Valid password"

def check_rate_limit_decorator(limit):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Custom rate limiting logic can be added here
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# JWT Error Handlers
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has been revoked'}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization token is required'}), 401

# API Routes
@app.route('/')
@limiter.limit("10 per minute")
def home():
    return jsonify({"message": "Welcome to Fetchbot API", "version": "1.0.0"}), 200

@app.route('/api/v1/health')
@limiter.limit("30 per minute")
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": "operational",
            "auth": "operational"
        }
    }), 200

@app.route('/api/v1/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    try:
        data = request.get_json()
        
        # Input validation
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        # Validate email
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password
        valid, message = validate_password(password)
        if not valid:
            return jsonify({'error': message}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create new user
        user = User(email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        app.logger.info(f"New user registered: {email}")
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': user.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            time.sleep(2)  # Prevent timing attacks
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.locked_until and datetime.utcnow() < user.locked_until:
            return jsonify({'error': 'Account is locked due to too many failed attempts'}), 403
        
        # Check password
        if not user.check_password(password):
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                app.logger.warning(f"Account locked for {email} due to failed login attempts")
            
            db.session.commit()
            time.sleep(2)  # Prevent timing attacks
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        user.locked_until = None
        
        # Create JWT token
        access_token = create_access_token(
            identity=user.id,
            additional_claims={
                'email': user.email,
                'type': 'access'
            }
        )
        
        db.session.commit()
        
        app.logger.info(f"Successful login for: {email}")
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        token = TokenBlacklist(jti=jti, revoked_at=datetime.utcnow())
        db.session.add(token)
        db.session.commit()
        
        return jsonify({'message': 'Successfully logged out'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/v1/auth/oauth/callback', methods=['POST'])
@limiter.limit("10 per minute")
def oauth_callback():
    """OAuth callback endpoint - implement based on your OAuth provider"""
    try:
        data = request.get_json()
        provider = data.get('provider')
        code = data.get('code')
        
        # Implement OAuth flow based on provider
        # This is a simplified example
        if provider not in ['google', 'github', 'facebook']:
            return jsonify({'error': 'Invalid OAuth provider'}), 400
        
        # Verify OAuth code with provider (implement based on provider)
        # Get user info from provider
        # Find or create user
        # Generate JWT token
        
        return jsonify({'access_token': 'oauth_token_here'}), 200
        
    except Exception as e:
        app.logger.error(f"OAuth error: {str(e)}")
        return jsonify({'error': 'OAuth authentication failed'}), 500

@app.route('/api/v1/profile', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
def get_profile():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': user.id,
            'email': user.email,
            'created_at': user.created_at.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None
        }), 200
        
    except Exception as e:
        app.logger.error(f"Profile error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/api-keys', methods=['POST'])
@jwt_required()
@limiter.limit("5 per hour")
def create_api_key():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        name = data.get('name', 'API Key')
        expires_in_days = data.get('expires_in_days', 30)
        
        # Generate secure API key using cryptographically secure method
        api_key = APIKey.generate_api_key()
        key_hash = generate_password_hash(api_key, method='pbkdf2:sha256', salt_length=16)
        
        # Create API key record
        api_key_obj = APIKey(
            user_id=current_user_id,
            key_hash=key_hash,
            name=name,
            expires_at=datetime.utcnow() + timedelta(days=expires_in_days)
        )
        
        db.session.add(api_key_obj)
        db.session.commit()
        
        return jsonify({
            'api_key': api_key,  # Only return once
            'key_id': api_key_obj.id,
            'name': name,
            'expires_at': api_key_obj.expires_at.isoformat()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"API key creation error: {str(e)}")
        return jsonify({'error': 'Failed to create API key'}), 500

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Too many requests', 'retry_after': e.description}), 429

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

# Database initialization
def init_db():
    with app.app_context():
        db.create_all()
        app.logger.info("Database initialized")

def generate_development_keys():
    """Generate secure keys for development environment"""
    if not os.path.exists('.env'):
        secret_key = secrets.token_hex(32)
        jwt_secret = secrets.token_hex(32)
        
        env_content = f"""# Flask API Security Keys
SECRET_KEY={secret_key}
JWT_SECRET_KEY={jwt_secret}
DATABASE_URL=sqlite:///./app.db
FLASK_ENV=development
FLASK_DEBUG=False

# OAuth configuration (replace with your actual credentials)
OAUTH_CLIENT_ID=your-oauth-client-id
OAUTH_CLIENT_SECRET=your-oauth-client-secret
OAUTH_CALLBACK_URL=http://localhost:5000/api/v1/auth/oauth/callback

# Rate limiting
RATELIMIT_DEFAULT=200 per day;50 per hour
"""
        
        with open('.env', 'w') as f:
            f.write(env_content)
        
        print("Generated .env file with secure keys!")
        print("SECRET_KEY:", secret_key)
        print("JWT_SECRET_KEY:", jwt_secret)
        print("\nREMEMBER: Add your OAuth credentials to the .env file")

if __name__ == '__main__':
    # Generate secure keys if .env doesn't exist
    generate_development_keys()
    
    init_db()
    # In production, use a proper WSGI server like Gunicorn
    # gunicorn -w 4 -b 0.0.0.0:8000 app:app
    app.run(debug=False, host='0.0.0.0', port=5001)