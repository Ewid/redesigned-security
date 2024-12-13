from functools import wraps
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
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
from datetime import datetime, timedelta
import uuid

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

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
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        try:
            movie_name = request.form['movie_name']
            cast = request.form['cast']
            rating = request.form['rating']
            image = request.files['image']

            if movie_name and image:
                filename = secure_filename(image.filename)
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
                flash('Movie added successfully!')
            else:
                flash('Movie name and image are required!')
        except:
            flash('Error adding movie!')

    movies = Movie.query.filter_by(user_id=user_id).all()
    return render_template('dashboard.html', movies=movies, username=user.username)

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
    return response

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)