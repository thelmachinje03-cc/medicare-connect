import os
from cryptography.fernet import Fernet
from database import execute_query

# Load AES-256 key from environment
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise RuntimeError(
        "ENCRYPTION_KEY is missing from the environment variables. "
        "For security, a fallback key cannot be generated. Please generate a valid key using "
        "cryptography.fernet.Fernet.generate_key() and configure it as ENCRYPTION_KEY in your environment."
    )

try:
    cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8') if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
except Exception as e:
    raise RuntimeError(
        "ENCRYPTION_KEY is invalid. Please generate a valid key using "
        "cryptography.fernet.Fernet.generate_key() and configure it as ENCRYPTION_KEY in your environment."
    ) from e

def encrypt_val(val):
    """Encrypt a value using AES-256 Fernet."""
    if not val:
        return val
    try:
        return cipher_suite.encrypt(val.encode('utf-8')).decode('utf-8')
    except Exception:
        return val

def decrypt_val(val):
    """Decrypt a value using AES-256 Fernet. Falls back to raw text if decryption fails."""
    if not val:
        return val
    try:
        return cipher_suite.decrypt(val.encode('utf-8')).decode('utf-8')
    except Exception:
        return val


class User:
    def __init__(self, data):
        self.id = data['id']
        self.username = data['username']
        # Decrypt transparently on initialization
        self.email = decrypt_val(data['email'])
        self.phone = decrypt_val(data['phone'])
        self.password_hash = data['password_hash']
        self.role = data['role']
        self.created_at = data['created_at']

    @staticmethod
    def create(username, email, phone, password_hash, role):
        """Creates a new user, transparently encrypting email and phone fields."""
        encrypted_email = encrypt_val(email)
        encrypted_phone = encrypt_val(phone)
        query = """
            INSERT INTO users (username, email, phone, password_hash, role)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
        """
        result = execute_query(query, (username, encrypted_email, encrypted_phone, password_hash, role), fetch_one=True, commit=True)
        return result['id'] if result else None

    @staticmethod
    def get_by_id(user_id):
        """Retrieves a user by their ID."""
        query = "SELECT * FROM users WHERE id = %s;"
        result = execute_query(query, (user_id,), fetch_one=True)
        return User(result) if result else None

    @staticmethod
    def get_by_username(username):
        """Retrieves a user by their username."""
        query = "SELECT * FROM users WHERE username = %s;"
        result = execute_query(query, (username,), fetch_one=True)
        return User(result) if result else None

    @staticmethod
    def get_by_email(email):
        """
        Retrieves a user by their email address.
        Since AES-256 uses non-deterministic salts, we query all records and decrypt in Python.
        """
        query = "SELECT * FROM users;"
        results = execute_query(query, fetch_all=True)
        if results:
            for row in results:
                user = User(row)
                if user.email.lower() == email.lower():
                    return user
    @staticmethod
    def get_by_phone(phone):
        """
        Retrieves a user by their phone number.
        Since AES-256 uses non-deterministic salts, we query all records and decrypt in Python.
        """
        query = "SELECT * FROM users;"
        results = execute_query(query, fetch_all=True)
        if results:
            for row in results:
                user = User(row)
                if user.phone == phone:
                    return user
        return None

    @staticmethod
    def reset_password(user_id, password_hash):
        """Updates a user's password hash by user ID."""
        query = """
            UPDATE users
            SET password_hash = %s
            WHERE id = %s;
        """
        execute_query(query, (password_hash, user_id), commit=True)



class Doctor:
    def __init__(self, data):
        self.id = data['id']
        self.user_id = data['user_id']
        self.specialization = data['specialization']
        self.fee = data['fee']
        # Join-derived attributes transparently decrypted
        self.username = data.get('username')
        self.email = decrypt_val(data.get('email')) if data.get('email') else None
        self.phone = decrypt_val(data.get('phone')) if data.get('phone') else None

    @staticmethod
    def create(user_id, specialization, fee):
        """Creates a new doctor profile and returns the doctor ID."""
        query = """
            INSERT INTO doctors (user_id, specialization, fee)
            VALUES (%s, %s, %s)
            RETURNING id;
        """
        result = execute_query(query, (user_id, specialization, fee), fetch_one=True, commit=True)
        return result['id'] if result else None

    @staticmethod
    def get_by_id(doctor_id):
        """Retrieves a doctor by their doctor ID, joining with user data."""
        query = """
            SELECT d.*, u.username, u.email, u.phone
            FROM doctors d
            JOIN users u ON d.user_id = u.id
            WHERE d.id = %s;
        """
        result = execute_query(query, (doctor_id,), fetch_one=True)
        return Doctor(result) if result else None

    @staticmethod
    def get_by_user_id(user_id):
        """Retrieves a doctor profile using their underlying user ID."""
        query = """
            SELECT d.*, u.username, u.email, u.phone
            FROM doctors d
            JOIN users u ON d.user_id = u.id
            WHERE d.user_id = %s;
        """
        result = execute_query(query, (user_id,), fetch_one=True)
        return Doctor(result) if result else None

    @staticmethod
    def get_all():
        """Returns list of all registered doctors."""
        query = """
            SELECT d.*, u.username, u.email, u.phone
            FROM doctors d
            JOIN users u ON d.user_id = u.id
            ORDER BY u.username ASC;
        """
        results = execute_query(query, fetch_all=True)
        return [Doctor(row) for row in results] if results else []


class Appointment:
    def __init__(self, data):
        self.id = data['id']
        self.patient_id = data['patient_id']
        self.doctor_id = data['doctor_id']
        self.date = data['date']
        self.time = data['time']
        self.reason = data['reason']
        self.status = data['status']
        self.created_at = data['created_at']
        
        # Joined fields transparently decrypted
        self.patient_username = data.get('patient_username')
        self.patient_phone = decrypt_val(data.get('patient_phone')) if data.get('patient_phone') else None
        self.doctor_username = data.get('doctor_username')
        self.specialization = data.get('specialization')
        self.fee = data.get('fee')

    @staticmethod
    def create(patient_id, doctor_id, date, time, reason):
        """Creates a new appointment booking."""
        query = """
            INSERT INTO appointments (patient_id, doctor_id, date, time, reason)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
        """
        result = execute_query(query, (patient_id, doctor_id, date, time, reason), fetch_one=True, commit=True)
        return result['id'] if result else None

    @staticmethod
    def get_by_id(appointment_id):
        """Retrieves details of a specific appointment by ID."""
        query = """
            SELECT a.*, 
                   up.username AS patient_username, up.phone AS patient_phone,
                   ud.username AS doctor_username, d.specialization, d.fee
            FROM appointments a
            JOIN users up ON a.patient_id = up.id
            JOIN doctors d ON a.doctor_id = d.id
            JOIN users ud ON d.user_id = ud.id
            WHERE a.id = %s;
        """
        result = execute_query(query, (appointment_id,), fetch_one=True)
        return Appointment(result) if result else None

    @staticmethod
    def get_by_patient(patient_id):
        """Returns list of appointments booked by a specific patient."""
        query = """
            SELECT a.*, 
                   ud.username AS doctor_username, d.specialization, d.fee
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.id
            JOIN users ud ON d.user_id = ud.id
            WHERE a.patient_id = %s
            ORDER BY a.date DESC, a.time DESC;
        """
        results = execute_query(query, (patient_id,), fetch_all=True)
        return [Appointment(row) for row in results] if results else []

    @staticmethod
    def get_by_doctor(doctor_id, date=None):
        """Returns appointments scheduled with a doctor."""
        if date:
            query = """
                SELECT a.*, up.username AS patient_username, up.phone AS patient_phone
                FROM appointments a
                JOIN users up ON a.patient_id = up.id
                WHERE a.doctor_id = %s AND a.date = %s
                ORDER BY a.time ASC;
            """
            results = execute_query(query, (doctor_id, date), fetch_all=True)
        else:
            query = """
                SELECT a.*, up.username AS patient_username, up.phone AS patient_phone
                FROM appointments a
                JOIN users up ON a.patient_id = up.id
                WHERE a.doctor_id = %s
                ORDER BY a.date DESC, a.time DESC;
            """
            results = execute_query(query, (doctor_id,), fetch_all=True)
            
        return [Appointment(row) for row in results] if results else []

    @staticmethod
    def update_status(appointment_id, status):
        """Updates the status of an appointment."""
        query = """
            UPDATE appointments
            SET status = %s
            WHERE id = %s;
        """
        execute_query(query, (status, appointment_id), commit=True)

    @staticmethod
    def get_booked_times(doctor_id, date):
        """Returns list of booked time strings for a doctor on a specific date."""
        query = """
            SELECT time 
            FROM appointments 
            WHERE doctor_id = %s AND date = %s AND status != 'cancelled';
        """
        results = execute_query(query, (doctor_id, date), fetch_all=True)
        return [row['time'].strftime("%H:%M") for row in results] if results else []

    @staticmethod
    def reschedule(appointment_id, date, time):
        """Reschedules an appointment by date and time, resetting status to scheduled."""
        query = """
            UPDATE appointments
            SET date = %s, time = %s, status = 'scheduled'
            WHERE id = %s;
        """
        execute_query(query, (date, time, appointment_id), commit=True)

    @staticmethod
    def delete(appointment_id):
        """Physically deletes an appointment by ID."""
        query = "DELETE FROM appointments WHERE id = %s;"
        execute_query(query, (appointment_id,), commit=True)


class PasswordResetToken:
    @staticmethod
    def create(user_id, token_hash, expires_at):
        """Creates a new password reset token entry."""
        query = """
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
            RETURNING id;
        """
        result = execute_query(query, (user_id, token_hash, expires_at), fetch_one=True, commit=True)
        return result['id'] if result else None

    @staticmethod
    def get_valid_by_hash(token_hash):
        """Retrieves a token by its hash, verifying it has not expired in Python."""
        query = """
            SELECT * FROM password_reset_tokens
            WHERE token_hash = %s;
        """
        result = execute_query(query, (token_hash,), fetch_one=True)
        if result:
            import datetime
            if result['expires_at'] > datetime.datetime.now():
                return result
        return None

    @staticmethod
    def delete_by_user_id(user_id):
        """Deletes all password reset tokens for a user (e.g. after successful reset)."""
        query = "DELETE FROM password_reset_tokens WHERE user_id = %s;"
        execute_query(query, (user_id,), commit=True)
