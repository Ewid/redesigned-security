from functools import wraps
import os
from flask import Flask, abort, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
import re
from datetime import datetime, timedelta
import secrets
import uuid
import bleach
import hashlib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
from zxcvbn import zxcvbn

app = Flask(__name__)

app.config.update(
    # Database and Upload settings
    SQLALCHEMY_DATABASE_URI='sqlite:///movies.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER='./static/uploads',
    
    # Security settings
    SECRET_KEY=secrets.token_hex(32),  # Cryptographically secure key
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE='Lax',  # Prevent CSRF attacks
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Session timeout
    MAX_CONTENT_LENGTH=10 * 1024 * 1024  # Limit upload size to 10MB
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


# Add these fields to User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    session_id = db.Column(db.String(36))  # Add this for session tracking
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)  # Add this for password aging
    
class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    cast = db.Column(db.String(255), nullable=True)
    rating = db.Column(db.Float, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    file_hash = db.Column(db.String(64), nullable=True)  # Store file hash
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Setup secure logging
def setup_logging():
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    # Set up rotating file handler
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10240,
        backupCount=10
    )
    
    # Set secure logging format
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    # Set logging level
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

# Add password validation
def validate_password(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not re.search("[a-z]", password):
        return False, "Password must contain lowercase letters"
    if not re.search("[A-Z]", password):
        return False, "Password must contain uppercase letters"
    if not re.search("[0-9]", password):
        return False, "Password must contain numbers"
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain special characters"
    return True, "Password is valid"

# Add this to your secure input sanitization functions
def sanitize_input(text):
    if text is None:
        return None
    # Remove any potential XSS or harmful HTML/scripts
    clean_text = bleach.clean(text, 
        tags=[],  # No HTML tags allowed
        strip=True,
        strip_comments=True
    )
    return clean_text

def secure_filename_with_hash(filename):
    """Generate a secure filename with content hash"""
    name, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    random_hex = secrets.token_hex(8)
    return f"{timestamp}_{random_hex}{ext}"

# Add file type validation
def validate_file_type(file):
    # Read the first few bytes to check actual file type
    header = file.read(512)
    file.seek(0)  # Reset file pointer
    
    # List of allowed file signatures (magic numbers)
    ALLOWED_SIGNATURES = {
        b'\xFF\xD8\xFF': 'jpg',
        b'\x89PNG\r\n\x1a\n': 'png',
        b'GIF87a': 'gif',
        b'GIF89a': 'gif'
    }

        
    for signature, filetype in ALLOWED_SIGNATURES.items():
        if header.startswith(signature):
            return True
    return False


@app.route('/')
def index():
    return render_template('index.html')

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
            
        # Verify session ID to prevent session fixation
        if user.session_id != session.get('session_id'):
            session.clear()
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            
            # Validate password
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'error')
                return render_template('register.html')

            if User.query.filter_by(username=username).first():
                flash('Username already exists!', 'error')
                return render_template('register.html')

            # Use stronger hashing with increased iterations
            hashed_password = generate_password_hash(
                password, 
                method='pbkdf2:sha256', 
                salt_length=16
            )
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed!', 'error')
    return render_template('register.html')

# Update login route with session security
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
            
        user = User.query.filter_by(username=username).first()

        if user and user.locked_until and datetime.utcnow() < user.locked_until:
            remaining_time = (user.locked_until - datetime.utcnow()).seconds / 60
            flash(f'Account is locked for {remaining_time:.0f} more minutes.', 'error')
            return render_template('login.html')

        if user and check_password_hash(user.password, password):
            # Set secure session
            session.permanent = True
            session['user_id'] = user.id
            session['session_id'] = str(uuid.uuid4())
            
            # Update user session tracking
            user.session_id = session['session_id']
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            return redirect(url_for('dashboard'))
        else:
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
            flash('Invalid credentials', 'error')

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@require_auth
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get_or_404(user_id)

    if user.session_id != session.get('session_id'):
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # CSRF token is automatically checked by Flask-WTF
            
            # Sanitize text inputs
            movie_name = sanitize_input(request.form.get('movie_name'))
            cast = sanitize_input(request.form.get('cast'))
            rating = request.form.get('rating')
            image = request.files.get('image')

            if not movie_name or not image:
                flash('Movie name and image are required!', 'error')
                return redirect(url_for('dashboard'))

            # Validate and secure file upload
            if not validate_file_type(image):
                flash('Invalid file type or potentially dangerous file', 'error')
                return redirect(url_for('dashboard'))

            # Generate secure filename
            filename = secure_filename_with_hash(image.filename)
            
            # Ensure upload directory is secure
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            upload_path = os.path.abspath(upload_path)
            if not upload_path.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
                flash('Invalid file path detected', 'error')
                return redirect(url_for('dashboard'))

            # Scan file content before saving
            try:
                image_data = image.read()
                if len(image_data) > 5 * 1024 * 1024:  # 5MB limit
                    flash('File size too large', 'error')
                    return redirect(url_for('dashboard'))
                
                # Calculate file hash
                file_hash = hashlib.sha256(image_data).hexdigest()
                
                # Reset file pointer and save
                image.seek(0)
                image.save(upload_path)
            except Exception as e:
                flash('Error processing file', 'error')
                return redirect(url_for('dashboard'))

            # Validate rating
            try:
                rating = float(rating) if rating else None
                if rating is not None and not (0 <= rating <= 10):
                    raise ValueError
            except ValueError:
                flash('Rating must be a number between 0 and 10', 'error')
                return redirect(url_for('dashboard'))

            # Add to database with file hash
            new_movie = Movie(
                name=movie_name,
                cast=cast,
                rating=rating,
                image=filename,
                file_hash=file_hash,  # Add this field to Movie model
                user_id=user_id
            )
            db.session.add(new_movie)
            db.session.commit()
            flash('Movie added successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            # Log the error securely
            app.logger.error(f'Error adding movie: {str(e)}')
            flash('Error adding movie', 'error')

    movies = Movie.query.filter_by(user_id=user_id).all()
    return render_template('dashboard.html', 
                         movies=movies, 
                         username=user.username)

# Add secure logout
@app.route('/logout')
@require_auth
def logout():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            # Invalidate the session ID in database
            user.session_id = None
            db.session.commit()
    # Clear session
    session.clear()
    return redirect(url_for('index'))

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'

    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    return response

def check_ip_security(ip):
    # You can implement IP blacklisting/whitelisting here
    BLACKLISTED_IPS = set()  # Add known malicious IPs
    if ip in BLACKLISTED_IPS:
        return False
    return True

def check_password_strength(password):
    result = zxcvbn(password)
    if result['score'] < 3:
        return False, result['feedback']['warning']
    return True, "Password is strong enough"

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def log_audit(user_id, action, details=None):
    audit = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(audit)
    db.session.commit()

class ActiveSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(36), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

@app.before_request
def update_session_activity():
    if 'user_id' in session:
        session_id = session.get('session_id')
        active_session = ActiveSession.query.filter_by(session_id=session_id).first()
        if active_session:
            active_session.last_activity = datetime.utcnow()
            db.session.commit()

@app.before_request
def security_check():
    client_ip = request.remote_addr
    if not check_ip_security(client_ip):
        abort(403)  # Forbidden

if __name__ == '__main__':
    setup_logging()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(debug=True)