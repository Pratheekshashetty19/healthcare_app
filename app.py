from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_session import Session
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthcare.db'
app.config['SESSION_TYPE'] = 'filesystem'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'patient', 'doctor', 'admin'
    name = db.Column(db.String(150))
    email = db.Column(db.String(150))
    specialization = db.Column(db.String(150))  # For doctors
    available_timings = db.Column(db.String(150))  # For doctors
    age = db.Column(db.Integer)  # For patients
    gender = db.Column(db.String(50))  # For patients
    medical_history = db.Column(db.Text)  # For patients

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), default='pending')  # 'pending', 'confirmed', 'completed'

class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    details = db.Column(db.Text, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.now())

# Create database and seed initial admin
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(username='admin', password=hashed_pw, role='admin', name='Admin User')
        db.session.add(admin)
        db.session.commit()

# Middleware-like decorators for auth and roles
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def role_required(role):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if session.get('role') != role:
                flash('Access denied', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        email = request.form['email']
        age = request.form['age']
        gender = request.form['gender']
        medical_history = request.form['medical_history']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_pw, role='patient', name=name, email=email, age=age, gender=gender, medical_history=medical_history)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', role=session['role'])

@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        name = request.form['name']
        email = request.form['email']
        specialization = request.form.get('specialization')
        available_timings = request.form.get('available_timings')
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_pw, role=role, name=name, email=email, specialization=specialization, available_timings=available_timings)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_user.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    appointments = Appointment.query.filter(
        (Appointment.patient_id == session['user_id']) | (Appointment.doctor_id == session['user_id'])
    ).all()
    if request.method == 'POST':
        user.name = request.form.get('name', user.name)
        user.email = request.form.get('email', user.email)
        user.specialization = request.form.get('specialization', user.specialization)
        user.available_timings = request.form.get('available_timings', user.available_timings)
        user.age = request.form.get('age', user.age)
        user.gender = request.form.get('gender', user.gender)
        user.medical_history = request.form.get('medical_history', user.medical_history)
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user, appointments=appointments, role=session['role'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)