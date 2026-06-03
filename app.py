import os
import datetime
import logging
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, session, request, jsonify
from flask_wtf.csrf import CSRFProtect
import bcrypt
from dotenv import load_dotenv

from database import init_db, execute_query
from models import User, Doctor, Appointment
from forms import LoginForm, PatientRegisterForm, DoctorRegisterForm, AppointmentForm, RescheduleForm, ForgotPasswordForm, ResetPasswordForm

# Load Environment variables
load_dotenv()

app = Flask(__name__)

# Load SECRET_KEY from environment, raise RuntimeError if missing
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in environment")
app.secret_key = SECRET_KEY

# Enable CSRF Protection globally
csrf = CSRFProtect(app)

# Configure Activity Logger with simple format to avoid absolute paths and debugger PIN
logging.basicConfig(
    filename='appointments.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize Flask-Limiter with in-memory storage
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

@app.errorhandler(429)
def ratelimit_handler(e):
    """Render a custom HTML page for Rate Limit Exceeded (HTTP 429)."""
    return render_template('429.html'), 429


# Configure Content Security Policy
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net'
    ],
    'style-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com'
    ],
    'font-src': [
        '\'self\'',
        'https://fonts.gstatic.com',
        'https://cdn.jsdelivr.net'
    ],
    'img-src': [
        '\'self\'',
        'data:'
    ],
    'object-src': ['\'none\''],
    'base-uri': ['\'self\''],
    'frame-ancestors': ['\'none\''],
    'form-action': ['\'self\'']
}

# Initialize Flask-Talisman for security headers
from flask_talisman import Talisman
Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    force_https=os.getenv("FORCE_HTTPS", "False").lower() == "true",
    frame_options='DENY',
    strict_transport_security=True
)

# Configure secure session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict'
)

# Hide Server header and add security and cache headers to prevent information disclosure and cache stale pages
@app.after_request
def add_security_and_cache_headers(response):
    # Hide Server header
    response.headers.pop('Server', None)
    
    # Explicitly enforce key security headers (in case Talisman is bypassed or on HTTP)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Configure Cache-Control headers
    # Static files get long cache life; HTML pages get no-cache
    if request.path.startswith('/static/') or request.path.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot')):
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    else:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
    return response

# Mask Werkzeug and Python server information in local development environment
try:
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "SecureServer"
    WSGIRequestHandler.sys_version = ""
except ImportError:
    pass

# Initialize database schemas
try:
    init_db()
except Exception as e:
    logging.error(f"Failed to initialize database on startup: {e}")


# --- SECURITY UTILITIES (bcrypt & Decortors) ---

def hash_password(password):
    """Securely hash password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(hashed, password):
    """Verify password against bcrypt hash securely."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(recipient, subject, body):
    """Sends a real email using SMTP settings from the environment."""
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("MAIL_DEFAULT_SENDER", smtp_username)

    if not smtp_username or not smtp_password:
        logging.warning("SMTP credentials are not fully configured in the environment. Email sending skipped.")
        return False

    try:
        smtp_port = int(smtp_port) if smtp_port else 587
    except ValueError:
        smtp_port = 587

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        logging.info(f"EMAIL ATTEMPT: Attempting to send email to {recipient}...")
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        logging.info(f"EMAIL SUCCESS: Real email sent successfully to {recipient}.")
        return True
    except Exception as e:
        logging.error(f"EMAIL FAILURE: Failed to send email to {recipient}. Error: {e}")
        return False



def login_required(f):
    """Decorator to protect routes requiring authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    """Decorator to enforce role-based access control (RBAC)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for('login'))
            if session.get('role') != role:
                flash("Unauthorized access. You do not have permission to view that resource.", "danger")
                if session.get('role') == 'patient':
                    return redirect(url_for('patient_dashboard'))
                elif session.get('role') == 'doctor':
                    return redirect(url_for('doctor_dashboard'))
                else:
                    return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- TEMPLATE CONTEXT PROCESSORS ---

@app.context_processor
def inject_now():
    """Provides current datetime context and utility functions to all templates."""
    return {
        'now': datetime.datetime.now(),
        'hasattr': hasattr
    }


# --- ROUTES ---

@app.route('/')
def index():
    """Landing page."""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    """Handles user registration for patients."""
    if 'user_id' in session:
        if session.get('role') == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif session.get('role') == 'doctor':
            return redirect(url_for('doctor_dashboard'))

    form = PatientRegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        phone = form.phone.data.strip()
        pwd_hash = hash_password(form.password.data)
        role = 'patient'

        try:
            # Insert User securely using parameterized query in Model
            user_id = User.create(username, email, phone, pwd_hash, role)
            
            flash("Registration successful! Please log in.", "success")
            logging.info(f"USER REGISTRATION: Patient {username} registered successfully.")
            return redirect(url_for('login'))
        except Exception as e:
            flash("An error occurred during registration. Please try again.", "danger")
            logging.error(f"PATIENT REGISTRATION FAILURE: {e}")

    return render_template('register.html', form=form)


@app.route('/register_doctor', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=["POST"])
def register_doctor():
    """Handles user registration for doctors."""
    if 'user_id' in session:
        if session.get('role') == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif session.get('role') == 'doctor':
            return redirect(url_for('doctor_dashboard'))

    form = DoctorRegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        phone = form.phone.data.strip()
        pwd_hash = hash_password(form.password.data)
        role = 'doctor'
        specialization = form.specialization.data.strip()
        fee = form.fee.data

        try:
            # Insert User securely using parameterized query in Model
            user_id = User.create(username, email, phone, pwd_hash, role)
            
            # Create associated Doctor profile
            Doctor.create(user_id, specialization, fee)
                
            flash("Doctor registration successful! Please log in.", "success")
            logging.info(f"USER REGISTRATION: Doctor {username} registered successfully.")
            return redirect(url_for('login'))
        except Exception as e:
            flash("An error occurred during registration. Please try again.", "danger")
            logging.error(f"DOCTOR REGISTRATION FAILURE: {e}")

    return render_template('register_doctor.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per 5 minutes", methods=["POST"])
def login():
    """Authenticates users securely."""
    if 'user_id' in session:
        if session.get('role') == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif session.get('role') == 'doctor':
            return redirect(url_for('doctor_dashboard'))

    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        user = User.get_by_username(username)
        if user and check_password(user.password_hash, password):
            # Regenerate session ID on login to protect against session fixation
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash(f"Welcome back, {user.username}!", "success")
            logging.info(f"USER LOGIN: User {user.username} (ID: {user.id}) logged in.")
            
            # Handle redirection
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            
            if user.role == 'patient':
                return redirect(url_for('patient_dashboard'))
            elif user.role == 'doctor':
                return redirect(url_for('doctor_dashboard'))
        else:
            flash("Invalid username or password. Please try again.", "danger")
            logging.warning(f"LOGIN FAILURE: Failed login attempt for username '{username}' from {request.remote_addr}.")

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """Logs out users and clears session."""
    username = session.get('username')
    user_id = session.get('user_id')
    if user_id:
        logging.info(f"USER LOGOUT: User {username} (ID: {user_id}) logged out.")
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('index'))


# --- PATIENT PORTAL ---

@app.route('/dashboard/patient')
@login_required
@role_required('patient')
@limiter.limit("120 per minute", key_func=lambda: session.get('user_id'))
def patient_dashboard():
    """Renders the patient portal."""
    patient_id = session['user_id']
    appointments = Appointment.get_by_patient(patient_id)
    
    # Calculate stats
    total = len(appointments)
    upcoming = len([a for a in appointments if a.status in ('scheduled', 'confirmed')])
    completed = len([a for a in appointments if a.status == 'completed'])
    
    return render_template('patient_dashboard.html', 
                           appointments=appointments, 
                           total=total, 
                           upcoming=upcoming, 
                           completed=completed)


@app.route('/book', methods=['GET', 'POST'])
@login_required
@role_required('patient')
@limiter.limit("60 per minute", key_func=lambda: session.get('user_id'))
def book_appointment():
    """Allows patient to book an appointment with validation."""
    patient_id = session['user_id']
    doctors = Doctor.get_all()
    
    form = AppointmentForm()
    # Dynamically populate doctor list choices
    form.doctor_id.choices = [(d.id, f"Dr. {d.username} ({d.specialization}) - {d.fee:,.0f} FCFA") for d in doctors]
    
    # Dynamic WTForms choices validation for the submitted time slot
    selected_doctor_id = form.doctor_id.data or (doctors[0].id if doctors else None)
    selected_date = form.date.data
    
    if selected_doctor_id and isinstance(selected_date, datetime.date):
        booked = Appointment.get_booked_times(selected_doctor_id, selected_date)
        all_slots = ["09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00"]
        
        valid_slots = []
        for slot in all_slots:
            if slot in booked:
                continue
            valid_slots.append((slot, slot))
        form.time.choices = valid_slots
    else:
        form.time.choices = []

    if form.validate_on_submit():
        doctor_id = form.doctor_id.data
        date = form.date.data
        time = form.time.data
        reason = form.reason.data.strip()

        try:
            # Attempt to save appointment securely (uniqueness caught by DB and python validation)
            appointment_id = Appointment.create(patient_id, doctor_id, date, time, reason)
            
            if appointment_id:
                flash("Appointment booked successfully!", "success")
                logging.info(f"BOOKING SUCCESS: Patient ID {patient_id} booked Appointment ID {appointment_id} with Doctor ID {doctor_id} on {date} at {time}.")
                return redirect(url_for('patient_dashboard'))
            else:
                flash("The selected slot is no longer available. Please choose another time.", "danger")
        except Exception as e:
            # Handle unique constraint violation gracefully
            flash("Error: This doctor already has an appointment booked for that specific slot.", "danger")
            logging.error(f"BOOKING CONFLICT/FAILURE: Patient {patient_id} with Doctor {doctor_id} on {date} {time}. Error: {e}")

    return render_template('book_appointment.html', form=form, doctors=doctors)


@app.route('/cancel/<int:appointment_id>', methods=['POST'])
@login_required
@role_required('patient')
@limiter.limit("30 per minute", key_func=lambda: session.get('user_id'))
def cancel_appointment(appointment_id):
    """Allows patient to cancel their booked appointment."""
    patient_id = session['user_id']
    appointment = Appointment.get_by_id(appointment_id)
    
    if not appointment:
        flash("Appointment not found.", "danger")
        return redirect(url_for('patient_dashboard'))
        
    if appointment.patient_id != patient_id:
        flash("Unauthorized cancellation request.", "danger")
        logging.warning(f"UNAUTHORIZED CANCELLATION: Patient ID {patient_id} tried to cancel Appointment ID {appointment_id} belonging to Patient ID {appointment.patient_id}.")
        return redirect(url_for('patient_dashboard'))

    Appointment.update_status(appointment_id, 'cancelled')
    flash("Appointment has been cancelled successfully.", "success")
    logging.info(f"BOOKING CANCELLED: Patient ID {patient_id} cancelled Appointment ID {appointment_id}.")
    
    return redirect(url_for('patient_dashboard'))


# --- DOCTOR PORTAL ---

@app.route('/dashboard/doctor')
@login_required
@role_required('doctor')
@limiter.limit("120 per minute", key_func=lambda: session.get('user_id'))
def doctor_dashboard():
    """Renders the doctor portal."""
    user_id = session['user_id']
    doctor = Doctor.get_by_user_id(user_id)
    
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for('logout'))

    all_appointments = Appointment.get_by_doctor(doctor.id)
    
    today_str = datetime.date.today().strftime("%Y-%m-%d")
    
    # Categorize appointments
    today_appointments = []
    upcoming_appointments = []
    
    for a in all_appointments:
        a_date_str = a.date.strftime("%Y-%m-%d") if isinstance(a.date, datetime.date) else str(a.date)
        if a_date_str == today_str:
            today_appointments.append(a)
        else:
            upcoming_appointments.append(a)
            
    return render_template('doctor_dashboard.html',
                           doctor=doctor,
                           today_appointments=today_appointments,
                           upcoming_appointments=upcoming_appointments)


@app.route('/confirm/<int:appointment_id>', methods=['POST'])
@login_required
@role_required('doctor')
@limiter.limit("30 per minute", key_func=lambda: session.get('user_id'))
def confirm_appointment(appointment_id):
    """Allows doctor to mark an appointment as confirmed."""
    user_id = session['user_id']
    doctor = Doctor.get_by_user_id(user_id)
    appointment = Appointment.get_by_id(appointment_id)
    
    if not doctor or not appointment:
        flash("Resource not found.", "danger")
        return redirect(url_for('doctor_dashboard'))
        
    if appointment.doctor_id != doctor.id:
        flash("Unauthorized action.", "danger")
        logging.warning(f"UNAUTHORIZED UPDATE: Doctor ID {doctor.id} tried to confirm Appointment ID {appointment_id} belonging to Doctor ID {appointment.doctor_id}.")
        return redirect(url_for('doctor_dashboard'))

    Appointment.update_status(appointment_id, 'confirmed')
    flash("Appointment marked as Confirmed.", "success")
    logging.info(f"BOOKING CONFIRMED: Doctor ID {doctor.id} confirmed Appointment ID {appointment_id}.")
    
    return redirect(url_for('doctor_dashboard'))


@app.route('/complete/<int:appointment_id>', methods=['POST'])
@login_required
@role_required('doctor')
@limiter.limit("30 per minute", key_func=lambda: session.get('user_id'))
def complete_appointment(appointment_id):
    """Allows doctor to mark an appointment as completed."""
    user_id = session['user_id']
    doctor = Doctor.get_by_user_id(user_id)
    appointment = Appointment.get_by_id(appointment_id)
    
    if not doctor or not appointment:
        flash("Resource not found.", "danger")
        return redirect(url_for('doctor_dashboard'))
        
    if appointment.doctor_id != doctor.id:
        flash("Unauthorized action.", "danger")
        logging.warning(f"UNAUTHORIZED UPDATE: Doctor ID {doctor.id} tried to complete Appointment ID {appointment_id} belonging to Doctor ID {appointment.doctor_id}.")
        return redirect(url_for('doctor_dashboard'))

    Appointment.update_status(appointment_id, 'completed')
    flash("Appointment marked as Completed.", "success")
    logging.info(f"BOOKING COMPLETED: Doctor ID {doctor.id} completed Appointment ID {appointment_id}.")
    
    return redirect(url_for('doctor_dashboard'))


# --- API ENDPOINTS ---

@app.route('/get_available_times')
def get_available_times():
    """
    API endpoint returning unused time slots (9am - 5pm) for a doctor on a specific date.
    Usage: /get_available_times?doctor_id=X&date=YYYY-MM-DD
    """
    doctor_id = request.args.get('doctor_id')
    date_str = request.args.get('date')

    if not doctor_id or not date_str:
        return jsonify({"error": "Missing doctor_id or date parameter."}), 400

    try:
        doctor_id = int(doctor_id)
        # Parse date to validate format
        datetime.datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "Invalid format for doctor_id or date (expected YYYY-MM-DD)."}), 400

    # Get already booked times (excluding cancelled ones)
    booked_times = Appointment.get_booked_times(doctor_id, date_str)
    
    # Generate all standard hourly slots from 9:00 AM to 5:00 PM (starts)
    all_slots = ["09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00"]
    
    # Premium enhancement: If date is today, do not return slots in the past
    now = datetime.datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    
    available_times = []
    for slot in all_slots:
        if slot in booked_times:
            continue
        if date_str == today_str:
            slot_time = datetime.datetime.strptime(f"{date_str} {slot}", "%Y-%m-%d %H:%M")
            if slot_time <= now:
                continue
        available_times.append(slot)

    return jsonify({"available_times": available_times})


@app.route('/reschedule/<int:appointment_id>', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per minute", key_func=lambda: session.get('user_id'))
def reschedule_appointment(appointment_id):
    """Allows patient or doctor to reschedule an appointment."""
    appointment = Appointment.get_by_id(appointment_id)
    if not appointment:
        flash("Appointment not found.", "danger")
        return redirect(url_for('index'))
        
    user_id = session['user_id']
    user_role = session['role']
    
    # Verify authorization
    if user_role == 'patient' and appointment.patient_id != user_id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('patient_dashboard'))
    if user_role == 'doctor':
        doctor = Doctor.get_by_user_id(user_id)
        if not doctor or appointment.doctor_id != doctor.id:
            flash("Unauthorized action.", "danger")
            return redirect(url_for('doctor_dashboard'))
            
    form = RescheduleForm()
    
    # Pre-populate date on GET
    if request.method == 'GET' and not form.date.data:
        form.date.data = appointment.date

    selected_date = form.date.data
    
    if isinstance(selected_date, datetime.date):
        booked = Appointment.get_booked_times(appointment.doctor_id, selected_date)
        all_slots = ["09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00"]
        
        valid_slots = []
        for slot in all_slots:
            # Allow the appointment's currently booked slot as a choice during reschedule!
            if slot in booked and not (appointment.date == selected_date and appointment.time.strftime("%H:%M") == slot):
                continue
            valid_slots.append((slot, slot))
        form.time.choices = valid_slots
    else:
        form.time.choices = []
        
    if form.validate_on_submit():
        new_date = form.date.data
        new_time = form.time.data
        
        try:
            Appointment.reschedule(appointment_id, new_date, new_time)
            flash("Appointment rescheduled successfully!", "success")
            logging.info(f"BOOKING RESCHEDULED: Appointment ID {appointment_id} rescheduled to {new_date} at {new_time} by User ID {user_id} ({user_role}).")
            
            if user_role == 'patient':
                return redirect(url_for('patient_dashboard'))
            else:
                return redirect(url_for('doctor_dashboard'))
        except Exception as e:
            flash("Failed to reschedule. That slot may already be booked.", "danger")
            logging.error(f"RESCHEDULE CONFLICT: Appointment ID {appointment_id} to {new_date} {new_time}. Error: {e}")
            
    return render_template('reschedule_appointment.html', form=form, appointment=appointment)


@app.route('/reject/<int:appointment_id>', methods=['POST'])
@login_required
@role_required('doctor')
@limiter.limit("30 per minute", key_func=lambda: session.get('user_id'))
def reject_appointment(appointment_id):
    """Allows doctor to reject (cancel) a patient's appointment request."""
    user_id = session['user_id']
    doctor = Doctor.get_by_user_id(user_id)
    appointment = Appointment.get_by_id(appointment_id)
    
    if not doctor or not appointment:
        flash("Resource not found.", "danger")
        return redirect(url_for('doctor_dashboard'))
        
    if appointment.doctor_id != doctor.id:
        flash("Unauthorized action.", "danger")
        logging.warning(f"UNAUTHORIZED REJECT: Doctor ID {doctor.id} tried to reject Appointment ID {appointment_id} belonging to Doctor ID {appointment.doctor_id}.")
        return redirect(url_for('doctor_dashboard'))
        
    Appointment.update_status(appointment_id, 'cancelled')
    flash("Appointment rejected successfully.", "success")
    logging.info(f"BOOKING REJECTED: Doctor ID {doctor.id} rejected Appointment ID {appointment_id}.")
    
    return redirect(url_for('doctor_dashboard'))


@app.route('/delete/<int:appointment_id>', methods=['POST'])
@login_required
@limiter.limit("30 per minute", key_func=lambda: session.get('user_id'))
def delete_appointment(appointment_id):
    """Allows patient or doctor to delete a completed or cancelled appointment from history."""
    appointment = Appointment.get_by_id(appointment_id)
    if not appointment:
        flash("Appointment not found.", "danger")
        return redirect(url_for('index'))
        
    user_id = session['user_id']
    user_role = session['role']
    
    # Check authorization
    if user_role == 'patient' and appointment.patient_id != user_id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('patient_dashboard'))
    if user_role == 'doctor':
        doctor = Doctor.get_by_user_id(user_id)
        if not doctor or appointment.doctor_id != doctor.id:
            flash("Unauthorized action.", "danger")
            return redirect(url_for('doctor_dashboard'))
            
    Appointment.delete(appointment_id)
    flash("Appointment record deleted completely.", "success")
    logging.info(f"BOOKING DELETED: Appointment ID {appointment_id} physically deleted by User ID {user_id} ({user_role}).")
    
    if user_role == 'patient':
        return redirect(url_for('patient_dashboard'))
    else:
        return redirect(url_for('doctor_dashboard'))


@app.route('/forgot', methods=['GET', 'POST'])
@limiter.limit("30 per hour", methods=["POST"])
def forgot_password():
    """Allows users to securely request a password reset."""
    if 'user_id' in session:
        if session.get('role') == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif session.get('role') == 'doctor':
            return redirect(url_for('doctor_dashboard'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        phone = form.phone.data.strip()

        user = User.get_by_username(username)
        if user and user.email.lower() == email and user.phone == phone:
            import secrets
            import hashlib
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
            
            # Calculate expiration: 15 minutes from now
            expires_at = datetime.datetime.now() + datetime.timedelta(minutes=15)
            
            from models import PasswordResetToken
            # Store in database
            PasswordResetToken.create(user.id, token_hash, expires_at)
            
            # Generate reset URL dynamically using url_for with _external=True
            reset_link = url_for('reset_password', token=raw_token, _external=True)
            
            # If the request is HTTPS (e.g. behind proxy on Render), ensure scheme matches
            if request.headers.get('X-Forwarded-Proto', 'http') == 'https':
                reset_link = url_for('reset_password', token=raw_token, _external=True, _scheme='https')
            
            email_body = f"""Hello,

You are receiving this email because a password reset request was made for your MediCare Connect account.

Click the link below to choose a new password:
{reset_link}

This link is valid for 15 minutes. If you did not request this, please ignore this email.

Best regards,
The MediCare Connect Team
"""
            sent = send_email(recipient=user.email, subject="Password Reset Request - MediCare Connect", body=email_body)
            
            # Log success and local testing details
            logging.info(f"PASSWORD RESET REQUEST: Secure reset token generated for user {username} (ID: {user.id}). SMTP Status: {sent}.")
            logging.info(f"LOCAL TESTING LINK: {reset_link}")
            
            flash("A password reset link has been sent to your email address.", "success")
            return redirect(url_for('login'))

        else:
            # Prevent details leakage
            flash("A password reset link has been sent to your email address.", "success")
            logging.warning(f"PASSWORD RESET REQUEST FAILURE: Failed reset request details for '{username}' from {request.remote_addr}.")
            return redirect(url_for('login'))

    return render_template('forgot_password.html', form=form)



@app.route('/reset/<token>', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=["POST"])
def reset_password(token):
    """Allows users to securely reset their password using a valid token."""
    if 'user_id' in session:
        if session.get('role') == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif session.get('role') == 'doctor':
            return redirect(url_for('doctor_dashboard'))

    import hashlib
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

    from models import PasswordResetToken
    # Verify token exists and is not expired
    reset_record = PasswordResetToken.get_valid_by_hash(token_hash)
    if not reset_record:
        flash("The password reset link is invalid or has expired.", "danger")
        logging.warning(f"PASSWORD RESET FAILURE: Attempted use of invalid/expired token hash: {token_hash} from {request.remote_addr}.")
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user_id = reset_record['user_id']
        new_pwd_hash = hash_password(form.new_password.data)
        
        # Update user's password
        User.reset_password(user_id, new_pwd_hash)
        
        # Invalidate/Delete used tokens
        PasswordResetToken.delete_by_user_id(user_id)
        
        flash("Password reset successful. Please log in with your new password.", "success")
        
        user = User.get_by_id(user_id)
        username = user.username if user else f"ID {user_id}"
        logging.info(f"PASSWORD RESET SUCCESS: User {username} (ID: {user_id}) reset password successfully via secure token.")
        
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, token=token)


if __name__ == '__main__':
    # Use gunicorn in production, never debug mode.
    app.run(debug=False, host='0.0.0.0', port=5000)


