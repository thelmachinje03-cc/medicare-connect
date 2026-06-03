import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DateField, TextAreaField, DecimalField
from wtforms.validators import DataRequired, InputRequired, Email, EqualTo, Length, Regexp, ValidationError, Optional
from models import User

def validate_password_complexity(form, field):
    r"""
    Validates password complexity:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - NO characters commonly used in injections: ' " ` \ ; -
    """
    password = field.data
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not any(c.isupper() for c in password):
        raise ValidationError("Password must contain at least one uppercase letter.")
        
    forbidden_chars = set("'\"`\\;-")
    
    # Check for forbidden injection-related characters
    if any(c in forbidden_chars for c in password):
        raise ValidationError("Password contains forbidden characters commonly used for injections (quotes, semicolons, backslashes, or dashes).")


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required.")
    ])


class PatientRegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters."),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, or underscores.")
    ])
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please enter a valid email address (e.g. user@domain.com)."),
        Length(max=100, message="Email must be under 100 characters.")
    ])
    phone = StringField('Phone Number', validators=[
        DataRequired(message="Phone number is required."),
        Regexp(r'^6[0-9]{8}$', message="Phone number must start with 6 and contain exactly 9 digits.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        validate_password_complexity
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo('password', message="Passwords must match.")
    ])

    def validate_username(self, field):
        """Ensure username is unique."""
        user = User.get_by_username(field.data)
        if user:
            raise ValidationError("This username is already taken. Please choose another.")

    def validate_email(self, field):
        """Ensure email is unique."""
        user = User.get_by_email(field.data.strip().lower())
        if user:
            raise ValidationError("This email is already registered. Please use another or log in.")




class DoctorRegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters."),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, or underscores.")
    ])
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please enter a valid email address (e.g. user@domain.com)."),
        Length(max=100, message="Email must be under 100 characters.")
    ])
    phone = StringField('Phone Number', validators=[
        DataRequired(message="Phone number is required."),
        Regexp(r'^6[0-9]{8}$', message="Phone number must start with 6 and contain exactly 9 digits.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        validate_password_complexity
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo('password', message="Passwords must match.")
    ])
    specialization = StringField('Specialization', validators=[
        DataRequired(message="Specialization is required."),
        Length(min=2, max=100, message="Specialization must be between 2 and 100 characters.")
    ])
    fee = DecimalField('Consultation Fee (FCFA)', validators=[
        InputRequired(message="Consultation fee is required.")
    ])

    def validate_username(self, field):
        """Ensure username is unique."""
        user = User.get_by_username(field.data)
        if user:
            raise ValidationError("This username is already taken. Please choose another.")

    def validate_email(self, field):
        """Ensure email is unique."""
        user = User.get_by_email(field.data.strip().lower())
        if user:
            raise ValidationError("This email is already registered. Please use another or log in.")



    def validate_fee(self, field):
        """Verify the fee is positive."""
        if field.data is not None and field.data < 0:
            raise ValidationError("Consultation fee must be a positive amount.")


class AppointmentForm(FlaskForm):
    doctor_id = SelectField('Select Doctor', coerce=int, validators=[
        DataRequired(message="Please select a doctor.")
    ])
    date = DateField('Appointment Date', format='%Y-%m-%d', validators=[
        DataRequired(message="Please select a date.")
    ])
    time = SelectField('Available Time Slot', choices=[], validators=[
        DataRequired(message="Please select an available time slot.")
    ])
    reason = TextAreaField('Reason for Visit', validators=[
        DataRequired(message="Please describe the reason for your visit."),
        Length(min=5, max=500, message="Reason must be between 5 and 500 characters.")
    ])

    def validate_date(self, field):
        """Ensure the appointment date is today or in the future."""
        if field.data is None:
            return
        if field.data < datetime.date.today():
            raise ValidationError("Appointment date must be in the future (today or later).")


class RescheduleForm(FlaskForm):
    date = DateField('New Appointment Date', format='%Y-%m-%d', validators=[
        DataRequired(message="Please select a date.")
    ])
    time = SelectField('Available Time Slot', choices=[], validators=[
        DataRequired(message="Please select an available time slot.")
    ])

    def validate_date(self, field):
        """Ensure the appointment date is today or in the future."""
        if field.data is None:
            return
        if field.data < datetime.date.today():
            raise ValidationError("Appointment date must be in the future (today or later).")


class ForgotPasswordForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required.")
    ])
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please enter a valid email address.")
    ])
    phone = StringField('Phone Number', validators=[
        DataRequired(message="Phone number is required.")
    ])


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="New password is required."),
        validate_password_complexity
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Please confirm your new password."),
        EqualTo('new_password', message="Passwords must match.")
    ])


