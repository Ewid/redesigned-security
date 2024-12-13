import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from datetime import timedelta
import re
import bleach
from functools import wraps
import secrets
import logging
from logging.handlers import RotatingFileHandler
import uuid
from OpenSSL import SSL

# Initialize Flask app with secure configurations
app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10MB max file size
    UPLOAD_FOLDER='./static/uploads',
    SQLALCHEMY_DATABASE_URI='sqlite:///movies.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

# Generate a strong secret key
app.secret_key = secrets.token_hex(32)

# Initialize security extensions
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'img-src': "'self' data:",
    'script-src': "'self'",
    'style-src': "'self' 'unsafe-inline'",
})

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application startup')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Security middleware
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Models with additional security fields
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_password_change = db.Column(db.DateTime)
    session_id = db.Column(db.String(36))
    movies = db.relationship('Movie', backref='user', lazy=True)

class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    cast = db.Column(db.String(255), nullable=True)
    rating = db.Column(db.Float, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def sanitize_input(text):
    return bleach.clean(text, strip=True)

def validate_password(password):
    if len(password) < 12:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def validate_file_type(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form['username'])
            password = request.form['password']

            if not validate_password(password):
                flash('Password must be at least 12 characters long and contain uppercase, lowercase, numbers, and special characters', 'error')
                return render_template('register.html')

            if User.query.filter_by(username=username).first():
                flash('Username already exists!', 'error')
                return render_template('register.html')

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            new_user = User(
                username=username,
                password=hashed_password,
                session_id=str(uuid.uuid4())
            )
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f'New user registered: {username}')
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred during registration', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.locked_until:
            if datetime.utcnow() < user.locked_until:
                flash('Account is temporarily locked. Please try again later.', 'error')
                return render_template('login.html')
            user.failed_login_attempts = 0
            user.locked_until = None

        if user and check_password_hash(user.password, password):
            session.permanent = True
            session['user_id'] = user.id
            session['session_id'] = str(uuid.uuid4())
            user.session_id = session['session_id']
            user.failed_login_attempts = 0
            db.session.commit()
            app.logger.info(f'Successful login: {username}')
            return redirect(url_for('dashboard'))
        else:
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
            app.logger.warning(f'Failed login attempt for username: {username}')
            flash('Invalid credentials', 'error')

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@require_auth
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if user.session_id != session.get('session_id'):
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            movie_name = sanitize_input(request.form['movie_name'])
            cast = sanitize_input(request.form['cast'])
            rating = float(request.form['rating']) if request.form['rating'] else None
            image = request.files['image']

            if not validate_file_type(image.filename):
                flash('Invalid file type. Only images allowed.', 'error')
                return redirect(url_for('dashboard'))

            filename = secure_filename(f"{uuid.uuid4()}_{image.filename}")
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)

            new_movie = Movie(
                name=movie_name,
                cast=cast,
                rating=rating,
                image=filename,
                user_id=user_id
            )
            db.session.add(new_movie)
            db.session.commit()
            flash('Movie added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error adding movie: {str(e)}')
            flash('Error adding movie', 'error')

    movies = Movie.query.filter_by(user_id=user_id).all()
    return render_template('dashboard.html', movies=movies, username=user.username)

@app.route('/logout')
@require_auth
def logout():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.session_id = None
            db.session.commit()
    session.clear()
    return redirect(url_for('index'))

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        db.create_all()
    ssl_context = ('server.crt', 'server.key')
    app.run(debug=True, ssl_context=ssl_context)