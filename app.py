from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import send_from_directory
import os
from config import Config
from datetime import datetime,date
from werkzeug.utils import secure_filename 


app = Flask(__name__)
app.config.from_object(Config)



UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False) # 'admin', 'doctor', 'patient'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.email} ({self.role})>'

class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Null until assigned
    date_time = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='Pending') # Pending, Confirmed, Cancelled, Completed


    patient = db.relationship('User', foreign_keys=[patient_id], backref='patient_appointments')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='doctor_appointments')



class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
 
    file_path = db.Column(db.String(255), nullable=False) 
    
    date_prescribed = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    patient = db.relationship('User', foreign_keys=[patient_id], backref='prescribed_to')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='prescribed_by')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class Availability(db.Model):
    __tablename__ = 'availability'
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    date_time = db.Column(db.DateTime, nullable=False)
    is_available = db.Column(db.Boolean, default=False) # True means free, False means blocked

    doctor = db.relationship('User', backref='availability_slots')

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash(f"Access denied. Only {role.capitalize()}s can access this page.", 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def create_initial_users():
    db.create_all()
    
    # Create default Admin if one doesn't exist
    if User.query.filter_by(role='admin').first() is None:
        admin = User(
            name=app.config['DEFAULT_ADMIN_NAME'],
            email=app.config['DEFAULT_ADMIN_EMAIL'],
            role='admin'
        )
        admin.set_password(app.config['DEFAULT_ADMIN_PASSWORD'])
        db.session.add(admin)
        db.session.commit()
        print("Default Admin created!")

# --- General Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/uploads/<filename>')
@login_required # Files are only visible to logged-in users
def uploaded_file(filename):
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    elif current_user.role == 'patient':
        return redirect(url_for('patient_dashboard'))
    
    flash("Your role is not recognized.", 'danger')
    return redirect(url_for('login'))

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f'Logged in successfully as {user.role.capitalize()}.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')

    return render_template('login.html', title='Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists.', 'warning')
            return redirect(url_for('register'))

        new_patient = User(name=name, email=email, role='patient')
        new_patient.set_password(password)
        db.session.add(new_patient)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', title='Patient Registration')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    doctor_count = User.query.filter_by(role='doctor').count()
    patient_count = User.query.filter_by(role='patient').count()
    return render_template('admin_dashboard.html', 
                           title='Admin Dashboard',
                           doctor_count=doctor_count,
                           patient_count=patient_count, User=User) 

@app.route('/add_user/<string:role_type>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user(role_type):
    if role_type not in ['admin', 'doctor']:
        flash('Invalid user type for registration.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash(f'An account with this email already exists.', 'warning')
            return render_template('add_user.html', role_type=role_type)

        new_user = User(name=name, email=email, role=role_type)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'{role_type.capitalize()} {name} added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_user.html', role_type=role_type, title=f'Add {role_type.capitalize()}')



@app.route('/doctor_dashboard')
@login_required
@role_required('doctor')
def doctor_dashboard():
   
    today = date.today()
    
    # Filter appointments by doctor_id, status='Confirmed', and where the date part matches today
    confirmed_today_count = Appointment.query.filter(
        Appointment.doctor_id == current_user.id,
        Appointment.status == 'Confirmed',
        # Check if the date_time column's date part equals today's date
        db.func.date(Appointment.date_time) == today
    ).count()

    # Get the list of patients for the prescription dropdown
    patients = User.query.filter_by(role='patient').all()
    
    return render_template('doctor_dashboard.html', 
                           title='Doctor Dashboard',
                           patients=patients, confirmed_today_count=confirmed_today_count)


@app.route('/doctor_appointments')
@login_required
@role_required('doctor')
def doctor_appointments():
    # Fetch all appointments where the doctor is assigned
    pending_appointments = Appointment.query.filter_by(doctor_id=current_user.id, status='Pending').all()
    
    # Fetch all patients for prescription use dropdown
    patients = User.query.filter_by(role='patient').all()
    
    return render_template('doctor_appointments.html', 
                           title='Doctor Actions', 
                           pending_appointments=pending_appointments,
                           patients=patients)

@app.route('/appointment_action/<int:appointment_id>/<string:action>')
@login_required
@role_required('doctor')
def appointment_action(appointment_id, action):
    appt = Appointment.query.get_or_404(appointment_id)
    
    if appt.doctor_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('doctor_appointments'))
        
    if action == 'confirm':
        appt.status = 'Confirmed'
        flash(f'Appointment on {appt.date_time.strftime("%Y-%m-%d %H:%M")} confirmed!', 'success')
    elif action == 'decline':
        appt.status = 'Declined'
        flash(f'Appointment on {appt.date_time.strftime("%Y-%m-%d %H:%M")} declined.', 'warning')
    else:
        flash('Invalid action.', 'danger')
        
    db.session.commit()
    return redirect(url_for('doctor_appointments'))

# app.py (New logic for file upload)

@app.route('/end_prescription', methods=['POST'])
@login_required
@role_required('doctor')
def end_prescription():
    patient_id = request.form.get('patient_id')
    
    if 'prescription_file' not in request.files:
        flash('No file part in the request.', 'danger')
        return redirect(url_for('doctor_appointments'))

    file = request.files['prescription_file']
    
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('doctor_appointments'))

    if file:
        # Create a safe, unique filename
        filename = secure_filename(f"{current_user.id}_{patient_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
        
        # Save the file to the UPLOAD_FOLDER
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Save the file path to the database
        new_prescription = Prescription(
            patient_id=patient_id,
            doctor_id=current_user.id,
            file_path=filename # Store only the filename relative to UPLOAD_FOLDER
        )
        
        db.session.add(new_prescription)
        db.session.commit()
        flash('Prescription file uploaded successfully!', 'success')
    else:
        flash('File upload failed.', 'danger')

    return redirect(url_for('doctor_appointments'))


@app.route('/manage_schedule', methods=['GET', 'POST'])
@login_required
@role_required('doctor')
def manage_schedule():
    if request.method == 'POST':
        date_str = request.form.get('date')
        time_str = request.form.get('time') # Optional for full-day block
        action = request.form.get('action') # 'block' or 'unblock'
        
        try:
            # 1. Handle Full Day Block (time_str is empty)
            if not time_str:
                date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
                
                # We will store full-day blocks as a specific time (e.g., 00:00:00) 
                # but use the 'is_full_day' flag to easily distinguish them.
                date_time_obj = datetime.combine(date_obj, datetime.min.time())
                is_full_day = True
                
            # 2. Handle Specific Time Block (time_str is provided)
            else:
                date_time_obj = datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')
                is_full_day = False
                
        except ValueError:
            flash('Invalid date or time format.', 'danger')
            return redirect(url_for('manage_schedule'))
            
        # Find existing slots (exact match for date_time_obj)
        slot = Availability.query.filter_by(doctor_id=current_user.id, date_time=date_time_obj).first()
        
        if action == 'block':
            if not slot:
                new_slot = Availability(
                    doctor_id=current_user.id,
                    date_time=date_time_obj,
                    is_available=False # Always False for a blocked slot
                )
                db.session.add(new_slot)
                # Flash appropriate message
                if is_full_day:
                    flash(f'Entire day of {date_str} successfully blocked.', 'danger')
                else:
                    flash(f'Time slot {date_time_obj.strftime("%H:%M")} successfully blocked.', 'danger')
            else:
                flash('This slot or day is already blocked.', 'warning')
        
        elif action == 'unblock':
            if slot:
                db.session.delete(slot) 
                flash(f'Slot/Day successfully unblocked.', 'success')
            else:
                flash('Time slot was not blocked. (Ensure the date and time match the original block)', 'warning')

        db.session.commit()
        return redirect(url_for('manage_schedule'))

    # GET request: show all blocked slots
    blocked_slots = Availability.query.filter_by(doctor_id=current_user.id, is_available=False).order_by(Availability.date_time).all()
    
    return render_template('manage_schedule.html', 
                           title='Manage Availability',
                           blocked_slots=blocked_slots)
# app.py (New code to display all appointments)
@app.route('/patient_dashboard')
@login_required
@role_required('patient')
def patient_dashboard():
    # Fetch ALL confirmed appointments for the current user, ordered by date
    all_appointments = Appointment.query.filter(
        Appointment.patient_id == current_user.id,
        Appointment.status.in_(['Confirmed', 'Completed']) # Include confirmed and completed visits
    ).order_by(Appointment.date_time.desc()).all() # <--- .all() gets everything

    # Find the single next upcoming appointment for the dashboard card display
    next_appointment = Appointment.query.filter(
        Appointment.patient_id == current_user.id,
        Appointment.status == 'Confirmed',
        Appointment.date_time >= datetime.now()
    ).order_by(Appointment.date_time.asc()).first()
    
    # Pass the list and the single next appointment data to the template
    return render_template('patient_dashboard.html', 
                           title='Patient Dashboard',
                           all_appointments=all_appointments,
                           next_appointment=next_appointment)



@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def book_appointment():
    doctors = User.query.filter_by(role='doctor').all()

    if request.method == 'POST':
        # ... (other form variable gathering remains the same) ...
        doctor_id = request.form.get('doctor_id')
        date_str = request.form.get('date')
        time_str = request.form.get('time')
        reason = request.form.get('reason')

        try:
            date_time_obj = datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')
            date_only_obj = datetime.strptime(date_str, '%Y-%m-%d') # Used for full-day check
        except ValueError:
            flash('Invalid date or time format.', 'danger')
            return redirect(url_for('book_appointment'))

        
        # 1. Check if the specific time slot is blocked
        is_blocked_slot = Availability.query.filter_by(
            doctor_id=doctor_id, 
            date_time=date_time_obj, 
            is_available=False
        ).first()

        # 2. Check if the entire day is blocked (stored as 00:00:00 on that date)
        is_blocked_day = Availability.query.filter_by(
            doctor_id=doctor_id, 
            date_time=date_only_obj, 
            is_available=False
        ).first()
        
        if is_blocked_slot or is_blocked_day:
            flash('Doctor not available at that time. Please choose a different date or time.', 'danger')
            return redirect(url_for('book_appointment'))

        # 3. Check if the doctor already has a CONFIRMED/PENDING appointment (existing logic)
        is_busy = Appointment.query.filter(
            Appointment.doctor_id == doctor_id,
            Appointment.date_time == date_time_obj,
            Appointment.status.in_(['Confirmed', 'Pending'])
        ).first()

        if is_busy:
            flash('Doctor is already booked for an appointment at that time. Please choose a different slot.', 'danger')
            return redirect(url_for('book_appointment'))
            
        # --- END VALIDATION LOGIC ---
        
        # ... (rest of the appointment creation logic remains the same) ...
        new_appointment = Appointment(
            patient_id=current_user.id,
            doctor_id=doctor_id,
            date_time=date_time_obj,
            reason=reason,
            status='Pending'
        )
        db.session.add(new_appointment)
        db.session.commit()
        
        flash('Appointment requested successfully! Awaiting doctor confirmation.', 'success')
        return redirect(url_for('patient_dashboard'))

    return render_template('book_appointment.html', title='Book Appointment', doctors=doctors)

# app.py (Add this route in a General Routes section)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Password Change Logic (POST request)
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # 1. Check if the old password is correct
        if not current_user.check_password(old_password):
            flash('Error: Your old password was incorrect.', 'danger')
            return redirect(url_for('profile'))

        # 2. Check if the new passwords match
        if new_password != confirm_password:
            flash('Error: New password and confirmation do not match.', 'danger')
            return redirect(url_for('profile'))

        # 3. Update the password
        current_user.set_password(new_password)
        db.session.commit()
        
        # Log out user for security after password change
        logout_user()
        flash('Password successfully updated. Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    # Profile View Logic (GET request)
    return render_template('profile.html', title=f'{current_user.role.capitalize()} Profile')

@app.route('/view_prescriptions')
@login_required
@role_required('patient')
def view_prescriptions():
    # Fetch all prescriptions for the current user, ordered by most recent first
    prescriptions = Prescription.query.filter_by(patient_id=current_user.id).order_by(Prescription.date_prescribed.desc()).all()
    
    return render_template('view_prescriptions.html', 
                           title='My Prescriptions',
                           prescriptions=prescriptions)

# app.py (Add this route in the Doctor Routes section)

@app.route('/doctor_patients')
@login_required
@role_required('doctor')
def doctor_patients():
    # Find unique patient IDs from confirmed/completed appointments with the current doctor
    patient_ids = db.session.query(Appointment.patient_id).filter(
        Appointment.doctor_id == current_user.id,
        Appointment.status.in_(['Confirmed', 'Completed'])
    ).distinct()

    # Fetch the User objects for those unique IDs
    my_patients = User.query.filter(User.id.in_(patient_ids)).all()
    
    return render_template('doctor_patients.html', 
                           title='My Patients',
                           my_patients=my_patients)

# app.py (Add this route in the Admin Routes section)

@app.route('/admin_view_users')
@login_required
@role_required('admin')
def admin_view_users():
    # Fetch all users, excluding the current Admin user for simplicity
    users = User.query.all()
    
    return render_template('admin_view_users.html', 
                           title='Admin User View',
                           users=users)

if __name__ == '__main__':
    with app.app_context():
        create_initial_users()
    app.run(debug=True)