import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///movies.db'
app.config['UPLOAD_FOLDER'] = './static/uploads'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    movies = db.relationship('Movie', backref='user', lazy=True)  # Add this line

class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    cast = db.Column(db.String(255), nullable=True)
    rating = db.Column(db.Float, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Add this line

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Username already exists!', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        try:
            movie_name = request.form['movie_name']
            cast = request.form['cast']
            rating = float(request.form['rating']) if request.form['rating'] else None
            image = request.files['image']

            if movie_name and image:
                # Save image
                filename = secure_filename(image.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(image_path)
                
                # Add movie to database with user_id
                new_movie = Movie(
                    name=movie_name,
                    cast=cast,
                    rating=rating,
                    image=filename,
                    user_id=user_id  # Add the user_id
                )
                db.session.add(new_movie)
                db.session.commit()
                flash('Movie added successfully!')
            else:
                flash('Movie name and image are required!')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding movie: {str(e)}')

    # Query only the current user's movies
    movies = Movie.query.filter_by(user_id=user_id).all()
    user = User.query.get(user_id)
    return render_template('dashboard.html', movies=movies, username=user.username)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        db.drop_all()  # Add this line to drop all tables
        db.create_all()  # This will recreate tables with the current schema
    app.run(debug=True)
