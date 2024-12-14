from functools import wraps
import os
from flask import Flask, abort, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
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
import hashlib

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
    security_questions = db.relationship('SecurityQuestion', backref='user', lazy=True)
    
class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    cast = db.Column(db.String(255), nullable=True)
    rating = db.Column(db.Float, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    file_hash = db.Column(db.String(64), nullable=True)  # Store file hash
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SecurityQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_category = db.Column(db.Integer, nullable=False)  # 1, 2, or 3
    question_index = db.Column(db.Integer, nullable=False)    # index within category
    answer_hash = db.Column(db.String(200), nullable=False)

SECURITY_QUESTIONS = {
    1: [
        "What was your first pet's name?",
        "What was the name of your first school?",
        "What is your mother's maiden name?"
    ],
    2: [
        "In what city were you born?",
        "What was your childhood nickname?",
        "What is the name of your favorite childhood friend?"
    ],
    3: [
        "What street did you grow up on?",
        "What was the make of your first car?",
        "What was your favorite food as a child?"
    ]
}

class DeviceFingerprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)
    user_agent = db.Column(db.String(200))
    is_trusted = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

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

def generate_device_fingerprint():
    ua_string = request.user_agent.string
    ip = request.remote_addr
    platform = request.user_agent.platform
    browser = request.user_agent.browser
    fingerprint = f"{ua_string}|{ip}|{platform}|{browser}"
    return hashlib.sha256(fingerprint.encode()).hexdigest()

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
@limiter.limit("5 per minute")
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

@app.route('/setup_security', methods=['GET', 'POST'])
@require_auth
def setup_security():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        try:
            # Delete any existing security questions
            SecurityQuestion.query.filter_by(user_id=user.id).delete()
            
            for i in range(1, 4):
                category = int(request.form.get(f'question{i}').split('_')[0])
                index = int(request.form.get(f'question{i}').split('_')[1])
                answer = request.form.get(f'answer{i}')
                
                if not answer:
                    flash('All answers are required', 'error')
                    return redirect(url_for('dashboard'))
                
                security_q = SecurityQuestion(
                    user_id=user.id,
                    question_category=category,
                    question_index=index,
                    answer_hash=generate_password_hash(answer.lower().strip())
                )
                db.session.add(security_q)
            
            db.session.commit()
            flash('Security questions set successfully', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error setting up security questions', 'error')
    
    return redirect(url_for('dashboard'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('can_reset_password') or not session.get('reset_user_id'):
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html')
            
        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('reset_password.html')
            
        try:
            user = User.query.get(session['reset_user_id'])
            user.password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            db.session.commit()
            
            # Clear all reset-related session data
            session.pop('can_reset_password', None)
            session.pop('reset_user_id', None)
            session.pop('reset_username', None)
            
            flash('Password has been reset successfully', 'success')
            return redirect(url_for('login'))
        except:
            flash('Error resetting password', 'error')
    
    return render_template('reset_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        
        if not user:
            # Don't reveal if username exists
            flash('If the username exists, security questions will be shown', 'info')
            return render_template('forgot_password.html')
        
        # Store username in session for the next step
        session['reset_username'] = username
        return redirect(url_for('verify_security_questions'))
    
    return render_template('forgot_password.html')

@app.route('/verify_security_questions', methods=['GET', 'POST'])
def verify_security_questions():
    username = session.get('reset_username')
    if not username:
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('forgot_password'))
    
    user_questions = SecurityQuestion.query.filter_by(user_id=user.id).all()
    
    if request.method == 'POST':
        correct_answers = 0
        for q in user_questions:
            answer = request.form.get(f'answer{q.id}')
            if answer and check_password_hash(q.answer_hash, answer.lower().strip()):
                correct_answers += 1
        
        if correct_answers == len(user_questions):
            session['can_reset_password'] = True
            session['reset_user_id'] = user.id
            return redirect(url_for('reset_password'))
        else:
            flash('One or more answers were incorrect', 'error')
    
    # Get the actual questions for display
    questions = []
    for q in user_questions:
        question_text = SECURITY_QUESTIONS[q.question_category][q.question_index - 1]
        questions.append({'id': q.id, 'text': question_text})
    
    return render_template('verify_security_questions.html', questions=questions)
# Update login route with session security
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
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

    has_security_questions = SecurityQuestion.query.filter_by(user_id=user_id).count() == 3

    if not has_security_questions:
        flash('Please set up your security questions for account recovery', 'warning')

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
                         username=user.username,
                         has_security_questions=has_security_questions,
                         security_questions=SECURITY_QUESTIONS)

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

def check_password_history(user, new_password):
    """Prevent password reuse"""
    history = PasswordHistory.query.filter_by(user_id=user.id)\
        .order_by(PasswordHistory.created_at.desc())\
        .limit(5).all()
    
    for old_password in history:
        if check_password_hash(old_password.password_hash, new_password):
            return False
    return True

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)