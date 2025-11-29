from flask import Flask, render_template_string, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from datetime import datetime, timedelta, date
import hashlib
import secrets
import random
import json
import os


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    SECRET_KEY = 'medicloud-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///medicloud.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'anurag120799@gmail.com'  # CHANGE THIS
    MAIL_PASSWORD = 'jmxz armo qbwp eoye'  # CHANGE THIS
    MAIL_DEFAULT_SENDER = 'anurag120799@gmail.com'

    OTP_EXPIRY_MINUTES = 10

    STATE_CODES = {
        'Jharkhand': 'JH', 'Maharashtra': 'MH', 'Delhi': 'DL',
        'West Bengal': 'WB', 'Karnataka': 'KA', 'Tamil Nadu': 'TN'
    }


# ============================================================================
# INITIALIZE FLASK APP
# ============================================================================

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'


# ============================================================================
# DATABASE MODELS
# ============================================================================

class SuperAdmin(UserMixin, db.Model):
    __tablename__ = 'super_admin'
    admin_id = db.Column(db.String(50), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_id(self):
        return self.admin_id

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == self.hash_password(password)


class Department(db.Model):
    __tablename__ = 'departments'
    dept_id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.String(50), db.ForeignKey('hospitals.hospital_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    head_doctor_id = db.Column(db.String(50), db.ForeignKey('hospital_staff.staff_id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PatientAdmission(db.Model):
    """Handles IPD (In-Patient Department) Lifecycle - FR-8"""
    __tablename__ = 'patient_admissions'
    admission_id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.String(50), db.ForeignKey('hospitals.hospital_id'), nullable=False)
    patient_id = db.Column(db.String(50), db.ForeignKey('patients_master.patient_id'), nullable=False)
    doctor_id = db.Column(db.String(50), db.ForeignKey('hospital_staff.staff_id'), nullable=False)
    room_number = db.Column(db.String(20), nullable=False)
    admission_date = db.Column(db.DateTime, default=datetime.utcnow)
    discharge_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='ADMITTED')  # ADMITTED, DISCHARGED
    reason = db.Column(db.Text)


class Hospital(UserMixin, db.Model):
    __tablename__ = 'hospitals'
    hospital_id = db.Column(db.String(50), primary_key=True)
    hospital_name = db.Column(db.String(200), nullable=False)
    license_number = db.Column(db.String(100), unique=True, nullable=False)
    address = db.Column(db.Text, nullable=False)
    state = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(100))
    admin_email = db.Column(db.String(120), unique=True, nullable=False)
    admin_mobile = db.Column(db.String(15), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    approval_status = db.Column(db.String(20), default='PENDING')
    approved_by = db.Column(db.String(50))
    approved_date = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=False)
    database_schema = db.Column(db.String(200))

    def get_id(self):
        return self.hospital_id

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == self.hash_password(password)


class HospitalStaff(UserMixin, db.Model):
    __tablename__ = 'hospital_staff'
    staff_id = db.Column(db.String(50), primary_key=True)
    hospital_id = db.Column(db.String(50), db.ForeignKey('hospitals.hospital_id'), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # DOCTOR, NURSE, PHARMACIST, RECEPTIONIST
    department = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)

    def get_id(self):
        return self.staff_id

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()


class Patient(UserMixin, db.Model):
    __tablename__ = 'patients_master'
    patient_id = db.Column(db.String(50), primary_key=True)
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    blood_group = db.Column(db.String(5))
    address = db.Column(db.Text)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    password_hash = db.Column(db.String(256), nullable=False)

    def get_id(self):
        return self.patient_id

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == self.hash_password(password)


class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    prescription_id = db.Column(db.String(50), primary_key=True)
    hospital_id = db.Column(db.String(50), db.ForeignKey('hospitals.hospital_id'), nullable=False)
    doctor_id = db.Column(db.String(50), db.ForeignKey('hospital_staff.staff_id'), nullable=False)
    patient_id = db.Column(db.String(50), db.ForeignKey('patients_master.patient_id'), nullable=False)
    diagnosis = db.Column(db.Text)
    medicines = db.Column(db.Text)  # Stored as JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Guest(UserMixin, db.Model):
    __tablename__ = 'guests'
    guest_id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)

    def get_id(self):
        return self.guest_id

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == self.hash_password(password)


class OTPVerification(db.Model):
    __tablename__ = 'otp_verification'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp_code = db.Column(db.String(10), nullable=False)
    otp_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)


class ApprovalQueue(db.Model):
    __tablename__ = 'approval_queue'
    approval_id = db.Column(db.Integer, primary_key=True)
    request_type = db.Column(db.String(50), nullable=False)
    request_data = db.Column(db.Text, nullable=False)
    hospital_id = db.Column(db.String(50))
    requested_by = db.Column(db.String(120), nullable=False)
    requested_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='PENDING')
    reviewed_by = db.Column(db.String(50))
    reviewed_date = db.Column(db.DateTime)
    comments = db.Column(db.Text)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_unique_id(prefix, state_code=None):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_suffix = secrets.token_hex(3).upper()
    if state_code:
        return f"{prefix}-{state_code}-{timestamp[-6:]}{random_suffix[:3]}"
    return f"{prefix}-{timestamp[-8:]}-{random_suffix}"


def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def send_otp_email(email, otp_code, purpose):
    try:
        msg = Message(
            subject=f'MediCloud - OTP Verification',
            recipients=[email]
        )
        msg.html = f"""
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">MediCloud HMS</h1>
            </div>
            <div style="padding: 30px; background: white;">
                <h2 style="color: #1e3c72;">OTP Verification</h2>
                <p>Your OTP for <strong>{purpose}</strong> is:</p>
                <div style="background: #e3f2fd; padding: 20px; text-align: center; margin: 20px 0;">
                    <h1 style="color: #1e3c72; font-size: 36px; letter-spacing: 8px;">{otp_code}</h1>
                </div>
                <p style="color: #666;">Valid for 10 minutes only.</p>
            </div>
        </div>
        """
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False


def store_otp(email, otp_code, otp_type):
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    otp = OTPVerification(email=email, otp_code=otp_code, otp_type=otp_type, expires_at=expires_at)
    db.session.add(otp)
    db.session.commit()


def verify_otp(email, otp_code, otp_type):
    otp = OTPVerification.query.filter_by(
        email=email, otp_code=otp_code, otp_type=otp_type, is_verified=False
    ).order_by(OTPVerification.created_at.desc()).first()

    if otp and datetime.utcnow() <= otp.expires_at:
        otp.is_verified = True
        db.session.commit()
        return True
    return False


@login_manager.user_loader
def load_user(user_id):
    user_type = session.get('user_type')
    if user_type == 'Super Admin':
        return SuperAdmin.query.get(user_id)
    elif user_type == 'Hospital':
        return Hospital.query.get(user_id)
    elif user_type == 'Staff':
        return HospitalStaff.query.get(user_id)
    elif user_type == 'Patient':
        return Patient.query.get(user_id)
    elif user_type == 'Guest':
        return Guest.query.get(user_id)
    return None


# ============================================================================
# HTML TEMPLATES (Embedded)
# ============================================================================

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediCloud - Hospital Management System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 15px 0; position: sticky; top: 0; z-index: 1000; }
        .header-top { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 20px; }
        .logo-section { display: flex; align-items: center; gap: 15px; }
        .logo { width: 60px; height: 60px; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold; color: #1e3c72; }
        .brand-text h1 { font-size: 20px; }
        .brand-text p { font-size: 10px; opacity: 0.9; }
        .btn-login { background: #ff6b35; color: white; padding: 12px 25px; border: none; border-radius: 25px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-block; }
        .login-dropdown { position: relative; display: inline-block; }
        .dropdown-content { display: none; position: absolute; right: 0; top: 50px; background: white; min-width: 280px; box-shadow: 0 8px 20px rgba(0,0,0,0.2); border-radius: 10px; overflow: hidden; z-index: 1001; }
        .dropdown-content.show { display: block; }
        .dropdown-header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 15px; text-align: center; font-weight: 600; font-size: 12px; }
        .dropdown-item { display: flex; align-items: center; padding: 15px 20px; color: #333; text-decoration: none; border-bottom: 1px solid #f0f0f0; transition: all 0.3s; }
        .dropdown-item:hover { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; }
        .dropdown-item .icon { width: 40px; height: 40px; background: #f0f0f0; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 20px; margin-right: 15px; }
        nav { background: rgba(255,255,255,0.1); }
        .nav-menu { display: flex; justify-content: center; list-style: none; padding: 12px 0; gap: 20px; }
        .nav-menu a { color: white; text-decoration: none; padding: 8px 15px; border-radius: 5px; }
        .hero-section { max-width: 1200px; margin: 40px auto; padding: 0 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 40px; align-items: center; }
        .hero-content h2 { font-size: 36px; color: #1e3c72; margin-bottom: 20px; }
        .hero-content p { font-size: 16px; color: #666; margin-bottom: 30px; }
        .btn-primary { background: #ff6b35; color: white; padding: 14px 30px; border: none; border-radius: 25px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-block; margin-right: 15px; }
        .btn-secondary { background: white; color: #1e3c72; padding: 14px 30px; border: 2px solid #1e3c72; border-radius: 25px; text-decoration: none; display: inline-block; }
        .feature-card { background: linear-gradient(135deg, #ff6b35 0%, #ff8c42 100%); border-radius: 20px; padding: 40px; color: white; }
        .feature-badge { background: rgba(255,255,255,0.2); padding: 8px 15px; border-radius: 20px; font-weight: 600; font-size: 12px; display: inline-block; }
        .registration-section { max-width: 1200px; margin: 60px auto; padding: 0 20px; }
        .section-title { text-align: center; font-size: 32px; color: #1e3c72; margin-bottom: 40px; }
        .registration-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; }
        .reg-card { background: white; padding: 30px; border-radius: 20px; box-shadow: 0 5px 20px rgba(0,0,0,0.1); text-align: center; border-top: 5px solid #1e3c72; }
        .reg-card.patient { border-top-color: #27ae60; }
        .reg-card.guest { border-top-color: #f39c12; }
        .reg-icon { font-size: 48px; margin-bottom: 20px; }
        .reg-features { list-style: none; text-align: left; margin: 20px 0; }
        .reg-features li { padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
        .reg-features li:before { content: "✓ "; color: #27ae60; font-weight: bold; }
        footer { background: #1a1a2e; color: white; padding: 40px 20px 20px; margin-top: 60px; text-align: center; }
    </style>
</head>
<body>
    <header>
        <div class="header-top">
            <div class="logo-section">
                <div class="logo">MC</div>
                <div class="brand-text">
                    <h1>MediCloud</h1>
                    <p>Multi-Tenant Healthcare Management Platform</p>
                </div>
            </div>
            <div class="login-dropdown">
                <button class="btn-login" onclick="toggleDropdown()">Login ▼</button>
                <div class="dropdown-content" id="loginDropdown">
                    <div class="dropdown-header">SELECT LOGIN TYPE</div>
                    <a href="/login/Hospital" class="dropdown-item">
                        <div class="icon">🏥</div>
                        <div><strong>Hospital Login</strong><br><small>Admin Access</small></div>
                    </a>
                    <a href="/login/staff" class="dropdown-item">
                        <div class="icon">🥼</div>
                        <div><strong>Staff Login</strong><br><small>Doctors & Nurses</small></div>
                    </a>
                    <a href="/login/Patient" class="dropdown-item">
                        <div class="icon">👤</div>
                        <div><strong>Patient Login</strong><br><small>View Records</small></div>
                    </a>
                    <a href="/login/Guest" class="dropdown-item">
                        <div class="icon">👁️</div>
                        <div><strong>Guest Access</strong><br><small>Browse Features</small></div>
                    </a>
                    <a href="/login/Super%20Admin" class="dropdown-item">
                        <div class="icon">🔐</div>
                        <div><strong>Super Admin</strong><br><small>System Owner</small></div>
                    </a>
                </div>
            </div>
        </div>
        <nav>
            <ul class="nav-menu">
                <li><a href="#home">🏠 Home</a></li>
                <li><a href="#registration">Register</a></li>
                <li><a href="#features">Features</a></li>
            </ul>
        </nav>
    </header>

    <section class="hero-section" id="home">
        <div class="hero-content">
            <h2>Transform Healthcare with Cloud Technology</h2>
            <p>Multi-tenant SaaS platform with Gmail OTP authentication. Secure, scalable, and ready in 24 hours.</p>
            <a href="#registration" class="btn-primary">Get Started Now</a>
            <a href="#" class="btn-secondary">Request Demo</a>
        </div>
        <div class="feature-card">
            <span class="feature-badge">✨ GMAIL OTP SECURED</span>
            <h3>One System, Infinite Possibilities</h3>
            <p>Complete data isolation for each hospital. Secure OTP authentication for all users.</p>
        </div>
    </section>

    <section class="registration-section" id="registration">
        <h2 class="section-title">Choose Your Registration Type</h2>
        <div class="registration-grid">
            <div class="reg-card hospital">
                <div class="reg-icon">🏥</div>
                <h3>Hospital Registration</h3>
                <p>Register your hospital with Gmail OTP verification</p>
                <ul class="reg-features">
                    <li>Gmail OTP Verification</li>
                    <li>Unique Hospital ID</li>
                    <li>Isolated Database</li>
                    <li>Admin Dashboard</li>
                </ul>
                <a href="/register/hospital" class="btn-primary">Register Hospital</a>
            </div>

            <div class="reg-card patient">
                <div class="reg-icon">👤</div>
                <h3>Patient Registration</h3>
                <p>Universal patient account with cross-hospital access</p>
                <ul class="reg-features">
                    <li>Gmail OTP Verification</li>
                    <li>Universal Patient ID</li>
                    <li>Cross-Hospital Records</li>
                    <li>Download Reports</li>
                </ul>
                <a href="/register/patient" class="btn-primary">Register Patient</a>
            </div>

            <div class="reg-card guest">
                <div class="reg-icon">👁️</div>
                <h3>Guest Access</h3>
                <p>Quick access to browse system features</p>
                <ul class="reg-features">
                    <li>Quick Gmail OTP</li>
                    <li>Hospital Directory</li>
                    <li>Read-Only Access</li>
                    <li>Upgrade Anytime</li>
                </ul>
                <a href="/register/guest" class="btn-primary">Get Guest Access</a>
            </div>
        </div>
    </section>

    <footer>
        <p>&copy; 2025 MediCloud Healthcare Platform. All rights reserved.</p>
        <p><strong>Default Super Admin:</strong> admin@medicloud.com / Admin@123</p>
    </footer>

    <script>
        function toggleDropdown() {
            document.getElementById('loginDropdown').classList.toggle('show');
        }
        window.onclick = function(e) {
            if (!e.target.matches('.btn-login')) {
                const dropdown = document.getElementById('loginDropdown');
                if (dropdown && dropdown.classList.contains('show')) {
                    dropdown.classList.remove('show');
                }
            }
        }
    </script>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ user_type }} Login - MediCloud</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-card { background: white; border-radius: 20px; max-width: 500px; width: 90%; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        .login-header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; border-radius: 20px 20px 0 0; text-align: center; }
        .login-body { padding: 30px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 600; }
        .form-control { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; }
        .btn-primary { width: 100%; background: #1e3c72; color: white; padding: 14px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; margin-bottom: 10px; }
        .btn-secondary { width: 100%; background: #27ae60; color: white; padding: 14px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
        .divider { text-align: center; margin: 20px 0; color: #999; }
        .login-footer { padding: 20px 30px; background: #f5f5f5; border-radius: 0 0 20px 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <h2>{{ user_type }} Login</h2>
            <p>Sign in to access your dashboard</p>
        </div>

        <div class="login-body">
            <form id="loginForm">
                <div class="form-group">
                    <label>Email Address *</label>
                    <input type="email" id="email" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Password *</label>
                    <input type="password" id="password" class="form-control" required>
                </div>
                <button type="submit" class="btn-primary">Login</button>
            </form>

            <div class="divider">OR</div>

            <button class="btn-secondary" onclick="showOtpLogin()">Login with Gmail OTP</button>

            <div id="otpSection" style="display: none; margin-top: 20px;">
                <div class="form-group">
                    <label>Gmail Address *</label>
                    <input type="email" id="otpEmail" class="form-control">
                </div>
                <button class="btn-primary" onclick="sendOtp()">Send OTP</button>

                <div id="otpInput" style="display: none; margin-top: 15px;">
                    <div class="form-group">
                        <label>Enter 6-Digit OTP *</label>
                        <input type="text" id="otpCode" class="form-control" maxlength="6">
                    </div>
                    <button class="btn-secondary" onclick="verifyOtp()">Verify & Login</button>
                </div>
            </div>
        </div>

        <div class="login-footer">
            <p><a href="/">← Back to Home</a></p>
        </div>
    </div>

    <script>
        const userType = "{{ user_type }}";

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            const res = await fetch('/login/submit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, password, user_type: userType})
            });
            const data = await res.json();

            if (data.success) {
                window.location.href = data.redirect;
            } else {
                alert(data.message || 'Login failed');
            }
        });

        function showOtpLogin() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('otpSection').style.display = 'block';
        }

        async function sendOtp() {
            const email = document.getElementById('otpEmail').value;
            if (!email) { alert('Enter email'); return; }

            const res = await fetch('/login/otp/send', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, user_type: userType})
            });
            const data = await res.json();

            if (data.success) {
                document.getElementById('otpInput').style.display = 'block';
                alert(data.message + (data.demo_otp ? '\\n\\nDemo OTP: ' + data.demo_otp : ''));
            }
        }

        async function verifyOtp() {
            const email = document.getElementById('otpEmail').value;
            const otp = document.getElementById('otpCode').value;

            const res = await fetch('/login/otp/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, otp, user_type: userType})
            });
            const data = await res.json();

            if (data.success) {
                window.location.href = data.redirect;
            } else {
                alert(data.message);
            }
        }
    </script>
</body>
</html>
"""

STAFF_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Staff Login</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        .btn { width: 100%; padding: 12px; background: #1e3c72; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; margin-top: 15px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
        h2 { text-align: center; color: #1e3c72; }
    </style>
</head>
<body>
    <div class="card">
        <h2>🥼 Staff Login</h2>
        <form action="/login/staff/submit" method="POST">
            <input type="text" name="hospital_id" placeholder="Hospital ID (Tenant ID)" required>
            <input type="email" name="email" placeholder="Staff Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn">Login</button>
        </form>
        <p style="text-align: center; margin-top: 20px;"><a href="/" style="text-decoration: none; color: #666;">← Back</a></p>
    </div>
</body>
</html>
"""

REGISTER_HOSPITAL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hospital Registration - MediCloud</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .reg-card { background: white; border-radius: 20px; max-width: 600px; width: 100%; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-height: 90vh; overflow-y: auto; }
        .reg-header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; text-align: center; border-radius: 20px 20px 0 0; }
        .reg-body { padding: 30px; }
        .info-box { background: #e3f2fd; border-left: 4px solid #1e3c72; padding: 15px; margin-bottom: 20px; border-radius: 5px; font-size: 13px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; }
        .form-control { width: 100%; padding: 10px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; }
        .btn-primary { width: 100%; background: #1e3c72; color: white; padding: 14px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
    </style>
</head>
<body>
    <div class="reg-card">
        <div class="reg-header">
            <h2>🏥 Hospital Registration</h2>
            <p>Register with Gmail OTP verification</p>
        </div>
        <div class="reg-body">
            <div class="info-box">
                <strong>📋 Process:</strong> Fill details → Gmail OTP → Admin approval → Activation
            </div>
            <form id="regForm">
                <div class="form-group">
                    <label>Hospital Name *</label>
                    <input type="text" name="name" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>License Number *</label>
                    <input type="text" name="license" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Address *</label>
                    <textarea name="address" class="form-control" rows="2" required></textarea>
                </div>
                <div class="form-group">
                    <label>State *</label>
                    <select name="state" class="form-control" required>
                        <option value="">Select State</option>
                        <option value="Jharkhand">Jharkhand</option>
                        <option value="Maharashtra">Maharashtra</option>
                        <option value="Delhi">Delhi</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Admin Gmail *</label>
                    <input type="email" name="email" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Mobile *</label>
                    <input type="tel" name="mobile" class="form-control" pattern="[0-9]{10}" required>
                </div>
                <div class="form-group">
                    <label>Password *</label>
                    <input type="password" name="password" class="form-control" minlength="8" required>
                </div>
                <button type="submit" class="btn-primary">Send Gmail OTP & Register</button>
            </form>
            <p style="text-align: center; margin-top: 20px;"><a href="/">← Back to Home</a></p>
        </div>
    </div>
    <script>
        document.getElementById('regForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);

            const res = await fetch('/register/hospital/submit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            const result = await res.json();

            if (result.success) {
                if (result.demo_otp) alert('Demo OTP: ' + result.demo_otp);
                window.location.href = result.redirect;
            } else {
                alert(result.message);
            }
        });
    </script>
</body>
</html>
"""

REGISTER_PATIENT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patient Registration - MediCloud</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .reg-card { background: white; border-radius: 20px; max-width: 600px; width: 100%; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-height: 90vh; overflow-y: auto; }
        .reg-header { background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%); color: white; padding: 30px; text-align: center; border-radius: 20px 20px 0 0; }
        .reg-body { padding: 30px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; }
        .form-control { width: 100%; padding: 10px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; }
        .btn-primary { width: 100%; background: #27ae60; color: white; padding: 14px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
    </style>
</head>
<body>
    <div class="reg-card">
        <div class="reg-header">
            <h2>👤 Patient Registration</h2>
            <p>Create your universal patient account</p>
        </div>
        <div class="reg-body">
            <form id="regForm">
                <div class="form-group">
                    <label>Full Name *</label>
                    <input type="text" name="name" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Date of Birth *</label>
                    <input type="date" name="dob" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Gender *</label>
                    <select name="gender" class="form-control" required>
                        <option value="">Select</option>
                        <option value="Male">Male</option>
                        <option value="Female">Female</option>
                        <option value="Other">Other</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Blood Group</label>
                    <select name="blood_group" class="form-control">
                        <option value="">Select</option>
                        <option value="A+">A+</option>
                        <option value="O+">O+</option>
                        <option value="B+">B+</option>
                        <option value="AB+">AB+</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Gmail *</label>
                    <input type="email" name="email" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Mobile *</label>
                    <input type="tel" name="mobile" class="form-control" pattern="[0-9]{10}" required>
                </div>
                <div class="form-group">
                    <label>Password *</label>
                    <input type="password" name="password" class="form-control" minlength="8" required>
                </div>
                <button type="submit" class="btn-primary">Send Gmail OTP & Register</button>
            </form>
            <p style="text-align: center; margin-top: 20px;"><a href="/">← Back</a></p>
        </div>
    </div>
    <script>
        document.getElementById('regForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);

            const res = await fetch('/register/patient/submit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            const result = await res.json();

            if (result.success) {
                if (result.demo_otp) alert('Demo OTP: ' + result.demo_otp);
                window.location.href = result.redirect;
            } else {
                alert(result.message);
            }
        });
    </script>
</body>
</html>
"""

OTP_VERIFICATION_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification - MediCloud</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .otp-card { background: white; border-radius: 20px; max-width: 500px; width: 90%; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        .otp-header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; text-align: center; border-radius: 20px 20px 0 0; }
        .otp-body { padding: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        .otp-input { width: 100%; padding: 15px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 24px; text-align: center; letter-spacing: 10px; font-weight: bold; }
        .btn-primary { width: 100%; background: #27ae60; color: white; padding: 14px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; margin-bottom: 10px; }
        .btn-secondary { width: 100%; background: #e0e0e0; color: #333; padding: 14px; border: none; border-radius: 8px; cursor: pointer; }
        .timer { color: #ff6b35; font-weight: bold; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="otp-card">
        <div class="otp-header">
            <h2>📧 Gmail OTP Verification</h2>
            <p>Enter the OTP sent to your email</p>
        </div>
        <div class="otp-body">
            <div class="form-group">
                <input type="text" id="otpInput" class="otp-input" maxlength="6" placeholder="000000" autofocus>
            </div>
            <p class="timer">Valid for: <span id="timer">10:00</span></p>
            <button class="btn-primary" onclick="verifyOtp()">Verify & Complete Registration</button>
            <button class="btn-secondary" onclick="window.location.href='/'">Cancel</button>
        </div>
    </div>
    <script>
        let timeLeft = 600;
        const timerInterval = setInterval(() => {
            if (timeLeft <= 0) {
                clearInterval(timerInterval);
                alert('OTP expired');
                return;
            }
            const min = Math.floor(timeLeft / 60);
            const sec = timeLeft % 60;
            document.getElementById('timer').textContent = min + ':' + sec.toString().padStart(2, '0');
            timeLeft--;
        }, 1000);

        async function verifyOtp() {
            const otp = document.getElementById('otpInput').value;
            if (!otp || otp.length !== 6) {
                alert('Enter 6-digit OTP');
                return;
            }

            const res = await fetch('/register/verify-otp/submit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({otp})
            });
            const data = await res.json();

            if (data.success) {
                alert(data.message);
                window.location.href = data.redirect;
            } else {
                alert(data.message);
            }
        }
    </script>
</body>
</html>
"""

DASHBOARD_SUPER_ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Super Admin Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .dashboard-header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .btn-logout { background: #ff6b35; color: white; padding: 10px 20px; border-radius: 20px; text-decoration: none; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; padding: 30px 40px; }
        .stat-card { background: white; padding: 30px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-value { font-size: 48px; font-weight: bold; color: #1e3c72; }
        .stat-label { font-size: 14px; color: #666; margin-top: 10px; }
        .content { padding: 0 40px 40px; }
        .approval-table { width: 100%; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .approval-table th, .approval-table td { padding: 15px; text-align: left; border-bottom: 1px solid #f0f0f0; }
        .approval-table th { background: #f5f5f5; font-weight: 600; }
        .btn-approve { background: #27ae60; color: white; padding: 8px 15px; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px; }
        .btn-reject { background: #e74c3c; color: white; padding: 8px 15px; border: none; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <h1>🔐 Super Admin Dashboard</h1>
        <a href="/logout" class="btn-logout">Logout</a>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{{ pending_count }}</div>
            <div class="stat-label">Pending Approvals</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ active_hospitals }}</div>
            <div class="stat-label">Active Hospitals</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ total_patients }}</div>
            <div class="stat-label">Total Patients</div>
        </div>
    </div>

    <div class="content">
        <h2 style="margin-bottom: 20px;">Pending Hospital Approvals</h2>
        <table class="approval-table">
            <thead>
                <tr>
                    <th>Hospital ID</th>
                    <th>Hospital Name</th>
                    <th>License</th>
                    <th>Email</th>
                    <th>Date</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for approval in pending_approvals %}
                <tr>
                    <td>{{ approval.hospital_id }}</td>
                    <td>{{ approval.hospital.hospital_name if approval.hospital else 'N/A' }}</td>
                    <td>{{ approval.hospital.license_number if approval.hospital else 'N/A' }}</td>
                    <td>{{ approval.requested_by }}</td>
                    <td>{{ approval.requested_date.strftime('%Y-%m-%d') }}</td>
                    <td>
                        <button class="btn-approve" onclick="approve({{ approval.approval_id }})">✅ Approve</button>
                        <button class="btn-reject" onclick="reject({{ approval.approval_id }})">❌ Reject</button>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <script>
        async function approve(id) {
            if (!confirm('Approve this hospital?')) return;
            const res = await fetch('/admin/approve/' + id, {method: 'POST'});
            const data = await res.json();
            alert(data.message);
            if (data.success) location.reload();
        }

        async function reject(id) {
            const reason = prompt('Enter rejection reason:');
            if (!reason) return;
            const res = await fetch('/admin/reject/' + id, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({reason})
            });
            const data = await res.json();
            alert(data.message);
            if (data.success) location.reload();
        }
    </script>
</body>
</html>
"""

DASHBOARD_HOSPITAL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Hospital Administration</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f4f6f9; }
        .sidebar { width: 250px; background: #1e3c72; color: white; height: 100vh; position: fixed; padding: 20px 0; }
        .sidebar-header { padding: 0 20px 20px; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .menu-item { display: block; padding: 15px 25px; color: rgba(255,255,255,0.8); text-decoration: none; transition: 0.3s; }
        .menu-item:hover, .menu-item.active { background: rgba(255,255,255,0.1); color: white; border-left: 4px solid #ff6b35; }
        .menu-item i { width: 30px; }
        .main-content { margin-left: 250px; padding: 30px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); display: flex; justify-content: space-between; align-items: center; }
        .stat-info h3 { font-size: 28px; color: #1e3c72; margin-bottom: 5px; }
        .stat-info p { color: #666; font-size: 14px; }
        .stat-icon { font-size: 40px; color: #ff6b35; opacity: 0.2; }
        .card { background: white; border-radius: 12px; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #eee; }
        .status-badge { padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }
        .status-admitted { background: #e3f2fd; color: #1565c0; }
        .status-discharged { background: #e8f5e9; color: #2e7d32; }
        .btn-action { padding: 8px 15px; border-radius: 5px; text-decoration: none; font-size: 13px; color: white; background: #1e3c72; }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <h3>🏥 MediCloud</h3>
            <small>Admin Portal</small>
        </div>
        <a href="/dashboard" class="menu-item active"><i class="fas fa-chart-line"></i> Dashboard</a>
        <a href="/hospital/departments" class="menu-item"><i class="fas fa-building"></i> Departments</a>
        <a href="/hospital/staff" class="menu-item"><i class="fas fa-user-md"></i> Staff Mgmt</a>
        <a href="/hospital/admissions" class="menu-item"><i class="fas fa-procedures"></i> IPD Admissions</a>
        <a href="/logout" class="menu-item"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </div>

    <div class="main-content">
        <div class="header">
            <div>
                <h1>{{ hospital.hospital_name }}</h1>
                <p style="color: #666;">License: {{ hospital.license_number }}</p>
            </div>
            <div>
                <span class="status-badge status-{{ 'discharged' if hospital.is_active else 'admitted' }}">
                    {{ 'ACTIVE' if hospital.is_active else 'INACTIVE' }}
                </span>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-info">
                    <h3>{{ stats.staff_count }}</h3>
                    <p>Total Staff</p>
                </div>
                <div class="stat-icon"><i class="fas fa-user-md"></i></div>
            </div>
            <div class="stat-card">
                <div class="stat-info">
                    <h3>{{ stats.dept_count }}</h3>
                    <p>Departments</p>
                </div>
                <div class="stat-icon"><i class="fas fa-building"></i></div>
            </div>
            <div class="stat-card">
                <div class="stat-info">
                    <h3>{{ stats.admitted_count }}</h3>
                    <p>Active In-Patients</p>
                </div>
                <div class="stat-icon"><i class="fas fa-procedures"></i></div>
            </div>
            <div class="stat-card">
                <div class="stat-info">
                    <h3>{{ stats.today_rx }}</h3>
                    <p>Prescriptions Today</p>
                </div>
                <div class="stat-icon"><i class="fas fa-file-prescription"></i></div>
            </div>
        </div>

        <div class="card">
            <h3>🛏️ Recent Admissions (IPD)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Patient</th>
                        <th>Room</th>
                        <th>Doctor</th>
                        <th>Admitted Date</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for admission in recent_admissions %}
                    <tr>
                        <td>{{ admission.patient_name }}</td>
                        <td>{{ admission.room_number }}</td>
                        <td>Dr. {{ admission.doctor_name }}</td>
                        <td>{{ admission.admission_date.strftime('%Y-%m-%d') }}</td>
                        <td><span class="status-badge status-admitted">Admitted</span></td>
                        <td><a href="/hospital/discharge/{{ admission.admission_id }}" class="btn-action">Discharge</a></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="6" style="text-align:center; padding: 20px;">No active admissions found.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

HOSPITAL_MANAGE_STAFF_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Manage Staff</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #eee; }
        input, select { padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-right: 10px; }
        .btn { padding: 10px 20px; background: #27ae60; color: white; border: none; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👥 Staff Management</h1>
            <a href="/dashboard" style="text-decoration: none; color: #1e3c72;">← Back to Dashboard</a>
        </div>

        <div class="card">
            <h3>Add New Staff Member</h3>
            <form action="/hospital/add-staff" method="POST" style="display: flex; gap: 10px; flex-wrap: wrap;">
                <input type="text" name="first_name" placeholder="First Name" required>
                <input type="text" name="last_name" placeholder="Last Name" required>
                <input type="email" name="email" placeholder="Email" required>
                <select name="role" required>
                    <option value="">Select Role</option>
                    <option value="DOCTOR">Doctor</option>
                    <option value="NURSE">Nurse</option>
                    <option value="RECEPTIONIST">Receptionist</option>
                    <option value="PHARMACIST">Pharmacist</option>
                </select>
                <input type="text" name="department" placeholder="Department" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" class="btn">Create User</button>
            </form>
        </div>

        <div class="card">
            <h3>Staff Directory</h3>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Role</th>
                        <th>Department</th>
                        <th>Email</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for staff in staff_members %}
                    <tr>
                        <td>{{ staff.first_name }} {{ staff.last_name }}</td>
                        <td><span style="background: #e8f5e9; color: #2e7d32; padding: 5px 10px; border-radius: 15px; font-size: 12px; font-weight: bold;">{{ staff.role }}</span></td>
                        <td>{{ staff.department }}</td>
                        <td>{{ staff.email }}</td>
                        <td>{{ 'Active' if staff.is_active else 'Inactive' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

DOCTOR_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Doctor Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f5f5f5; }
        .header { background: #1e3c72; color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .container { padding: 40px; max-width: 1200px; margin: 0 auto; }
        .grid { display: grid; grid-template-columns: 1fr 2fr; gap: 30px; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-control { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        .btn { background: #1e3c72; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; width: 100%; }
        .medicine-row { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 10px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>👨‍⚕️ Dr. {{ user.last_name }}</h1>
            <small>{{ user.department }} Department | {{ hospital_name }}</small>
        </div>
        <a href="/logout" style="color: white; text-decoration: none; border: 1px solid white; padding: 8px 15px; border-radius: 20px;">Logout</a>
    </div>

    <div class="container">
        <div class="grid">
            <div class="card">
                <h3>🔍 Find Patient</h3>
                <form action="/doctor/search-patient" method="POST">
                    <input type="text" name="search_term" class="form-control" placeholder="Patient ID, Phone or Name" required>
                    <button type="submit" class="btn">Search</button>
                </form>

                {% if patient %}
                <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee;">
                    <h4>Patient Found:</h4>
                    <p><strong>Name:</strong> {{ patient.full_name }}</p>
                    <p><strong>Age/Gender:</strong> {{ patient.gender }}</p>
                    <p><strong>ID:</strong> {{ patient.patient_id }}</p>
                </div>
                {% endif %}
            </div>

            <div class="card">
                <h3>📝 Create Prescription</h3>
                {% if patient %}
                <form action="/doctor/create-prescription" method="POST">
                    <input type="hidden" name="patient_id" value="{{ patient.patient_id }}">

                    <label><strong>Diagnosis</strong></label>
                    <textarea name="diagnosis" class="form-control" rows="3" required></textarea>

                    <label><strong>Medicines</strong></label>
                    <div id="medicine-container">
                        <div class="medicine-row">
                            <input type="text" name="med_name[]" placeholder="Medicine Name" class="form-control" style="margin:0" required>
                            <input type="text" name="med_dosage[]" placeholder="Dosage (e.g. 1-0-1)" class="form-control" style="margin:0" required>
                            <input type="text" name="med_duration[]" placeholder="Duration" class="form-control" style="margin:0" required>
                        </div>
                    </div>
                    <button type="button" onclick="addMedicineRow()" style="background: #eee; color: #333; margin-bottom: 20px;" class="btn">+ Add Medicine</button>

                    <button type="submit" class="btn" style="background: #27ae60;">Issue Prescription</button>
                </form>
                {% else %}
                <p style="color: #666; text-align: center; margin-top: 50px;">Please search for a patient first to create a prescription.</p>
                {% endif %}
            </div>
        </div>
    </div>

    <script>
        function addMedicineRow() {
            const div = document.createElement('div');
            div.className = 'medicine-row';
            div.innerHTML = `
                <input type="text" name="med_name[]" placeholder="Medicine Name" class="form-control" style="margin:0" required>
                <input type="text" name="med_dosage[]" placeholder="Dosage" class="form-control" style="margin:0" required>
                <input type="text" name="med_duration[]" placeholder="Duration" class="form-control" style="margin:0" required>
            `;
            document.getElementById('medicine-container').appendChild(div);
        }
    </script>
</body>
</html>
"""

DASHBOARD_PATIENT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patient Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .dashboard-header { background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .btn-logout { background: #ff6b35; color: white; padding: 10px 20px; border-radius: 20px; text-decoration: none; }
        .content { padding: 40px; }
        .info-card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <h1>👤 Patient Dashboard</h1>
        <a href="/logout" class="btn-logout">Logout</a>
    </div>

    <div class="content">
        <div class="info-card">
            <h3>Patient Information</h3>
            <p><strong>Patient ID:</strong> {{ patient.patient_id }}</p>
            <p><strong>Name:</strong> {{ patient.full_name }}</p>
            <p><strong>Email:</strong> {{ patient.email }}</p>
            <p><strong>Blood Group:</strong> {{ patient.blood_group or 'Not specified' }}</p>
        </div>
    </div>
</body>
</html>
"""

HOSPITAL_DEPARTMENTS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Manage Departments</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f5f5f5; padding: 40px; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-row { display: flex; gap: 10px; margin-bottom: 20px; }
        input, button { padding: 12px; border-radius: 5px; border: 1px solid #ddd; }
        input { flex: 1; }
        button { background: #1e3c72; color: white; font-weight: bold; cursor: pointer; border: none; }
        .dept-list { list-style: none; padding: 0; }
        .dept-item { padding: 15px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
            <h2>🏢 Hospital Departments</h2>
            <a href="/dashboard" style="text-decoration:none; color:#1e3c72;">Back to Dashboard</a>
        </div>

        <form action="/hospital/add-department" method="POST" class="form-row">
            <input type="text" name="name" placeholder="Department Name (e.g. Cardiology, Pediatrics)" required>
            <button type="submit">+ Add Department</button>
        </form>

        <ul class="dept-list">
            {% for dept in departments %}
            <li class="dept-item">
                <span><strong>{{ dept.name }}</strong></span>
                <span style="color: #666; font-size: 12px;">Created: {{ dept.created_at.strftime('%Y-%m-%d') }}</span>
            </li>
            {% else %}
            <p style="text-align:center; color:#999;">No departments added yet.</p>
            {% endfor %}
        </ul>
    </div>
</body>
</html>
"""

HOSPITAL_ADMISSIONS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPD Admissions</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f5f5f5; padding: 40px; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input, select, textarea { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        .btn { background: #27ae60; color: white; padding: 12px; border: none; border-radius: 5px; width: 100%; cursor: pointer; font-weight: bold; }
        label { font-weight: 600; display: block; margin-bottom: 5px; color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
            <h2>🛏️ New Patient Admission (IPD)</h2>
            <a href="/dashboard" style="text-decoration:none; color:#1e3c72;">Back to Dashboard</a>
        </div>

        <form action="/hospital/admit-patient" method="POST">
            <label>Select Patient</label>
            <select name="patient_id" required>
                <option value="">-- Search/Select Patient --</option>
                {% for p in patients %}
                <option value="{{ p.patient_id }}">{{ p.full_name }} (ID: {{ p.patient_id }})</option>
                {% endfor %}
            </select>

            <label>Assign Doctor</label>
            <select name="doctor_id" required>
                <option value="">-- Select Doctor --</option>
                {% for d in doctors %}
                <option value="{{ d.staff_id }}">Dr. {{ d.last_name }} ({{ d.department }})</option>
                {% endfor %}
            </select>

            <label>Room / Ward Number</label>
            <input type="text" name="room_number" placeholder="e.g. ICU-01 or Ward-104" required>

            <label>Admission Reason</label>
            <textarea name="reason" rows="3" placeholder="Reason for hospitalization..."></textarea>

            <button type="submit" class="btn">Admit Patient</button>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_GUEST_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guest Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .dashboard-header { background: linear-gradient(135deg, #f39c12 0%, #f1c40f 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .btn-logout { background: #ff6b35; color: white; padding: 10px 20px; border-radius: 20px; text-decoration: none; }
        .content { padding: 40px; }
        .hospitals-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .hospital-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <h1>👁️ Guest Dashboard</h1>
        <a href="/logout" class="btn-logout">Logout</a>
    </div>

    <div class="content">
        <h2 style="margin-bottom: 20px;">Active Hospitals</h2>
        <div class="hospitals-grid">
            {% for hospital in hospitals %}
            <div class="hospital-card">
                <h3>{{ hospital.hospital_name }}</h3>
                <p><strong>ID:</strong> {{ hospital.hospital_id }}</p>
                <p><strong>State:</strong> {{ hospital.state }}</p>
            </div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
"""


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)


@app.route('/login/<user_type>')
def login(user_type):
    return render_template_string(LOGIN_HTML, user_type=user_type)


@app.route('/login/submit', methods=['POST'])
def login_submit():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user_type = data.get('user_type')

    user = None
    if user_type == 'Super Admin':
        user = SuperAdmin.query.filter_by(email=email).first()
    elif user_type == 'Hospital':
        user = Hospital.query.filter_by(admin_email=email).first()
    elif user_type == 'Patient':
        user = Patient.query.filter_by(email=email).first()
    elif user_type == 'Guest':
        user = Guest.query.filter_by(email=email).first()

    if user and user.check_password(password):
        login_user(user)
        session['user_type'] = user_type
        return jsonify({'success': True, 'redirect': url_for('dashboard')})

    return jsonify({'success': False, 'message': 'Invalid credentials'})


# --- STAFF LOGIN ROUTES ---
@app.route('/login/staff')
def login_staff():
    return render_template_string(STAFF_LOGIN_HTML)


@app.route('/login/staff/submit', methods=['POST'])
def login_staff_submit():
    hospital_id = request.form.get('hospital_id')
    email = request.form.get('email')
    password = request.form.get('password')

    staff = HospitalStaff.query.filter_by(hospital_id=hospital_id, email=email).first()

    if staff and staff.check_password(password):
        login_user(staff)
        session['user_type'] = 'Staff'
        return redirect(url_for('dashboard'))

    flash('Invalid credentials or Hospital ID')
    return redirect(url_for('login_staff'))


@app.route('/login/otp/send', methods=['POST'])
def send_otp_route():
    data = request.get_json()
    email = data.get('email')
    user_type = data.get('user_type')

    otp_code = generate_otp()
    otp_type = f"LOGIN_{user_type.upper().replace(' ', '_')}"

    store_otp(email, otp_code, otp_type)

    if send_otp_email(email, otp_code, f"{user_type} Login"):
        return jsonify({'success': True, 'message': 'OTP sent'})

    return jsonify({'success': True, 'message': 'OTP sent', 'demo_otp': otp_code})


@app.route('/login/otp/verify', methods=['POST'])
def verify_otp_login():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    user_type = data.get('user_type')

    otp_type = f"LOGIN_{user_type.upper().replace(' ', '_')}"

    if verify_otp(email, otp, otp_type):
        user = None
        if user_type == 'Super Admin':
            user = SuperAdmin.query.filter_by(email=email).first()
        elif user_type == 'Hospital':
            user = Hospital.query.filter_by(admin_email=email).first()
        elif user_type == 'Patient':
            user = Patient.query.filter_by(email=email).first()
        elif user_type == 'Guest':
            user = Guest.query.filter_by(email=email).first()

        if user:
            login_user(user)
            session['user_type'] = user_type
            return jsonify({'success': True, 'redirect': url_for('dashboard')})

        return jsonify({'success': False, 'message': 'User not found'})

    return jsonify({'success': False, 'message': 'Invalid OTP'})


@app.route('/register/<user_type>')
def register(user_type):
    if user_type == 'hospital':
        return render_template_string(REGISTER_HOSPITAL_HTML)
    elif user_type == 'patient':
        return render_template_string(REGISTER_PATIENT_HTML)
    elif user_type == 'guest':
        return render_template_string(REGISTER_PATIENT_HTML)  # Reuse for simplicity
    return redirect(url_for('index'))


@app.route('/register/hospital/submit', methods=['POST'])
def register_hospital_submit():
    data = request.get_json()

    existing = Hospital.query.filter(
        (Hospital.license_number == data['license']) |
        (Hospital.admin_email == data['email'])
    ).first()

    if existing:
        return jsonify({'success': False, 'message': 'Hospital already registered'})

    otp_code = generate_otp()
    session['temp_registration'] = {'type': 'hospital', 'data': data}

    store_otp(data['email'], otp_code, 'HOSPITAL_REGISTRATION')

    if send_otp_email(data['email'], otp_code, 'Hospital Registration'):
        return jsonify({'success': True, 'redirect': url_for('verify_registration_otp')})

    return jsonify({'success': True, 'demo_otp': otp_code, 'redirect': url_for('verify_registration_otp')})


@app.route('/register/patient/submit', methods=['POST'])
def register_patient_submit():
    data = request.get_json()

    existing = Patient.query.filter_by(email=data['email']).first()
    if existing:
        return jsonify({'success': False, 'message': 'Email already registered'})

    otp_code = generate_otp()
    session['temp_registration'] = {'type': 'patient', 'data': data}

    store_otp(data['email'], otp_code, 'PATIENT_REGISTRATION')

    if send_otp_email(data['email'], otp_code, 'Patient Registration'):
        return jsonify({'success': True, 'redirect': url_for('verify_registration_otp')})

    return jsonify({'success': True, 'demo_otp': otp_code, 'redirect': url_for('verify_registration_otp')})


@app.route('/register/verify-otp')
def verify_registration_otp():
    return render_template_string(OTP_VERIFICATION_HTML)


@app.route('/register/verify-otp/submit', methods=['POST'])
def verify_registration_otp_submit():
    data = request.get_json()
    otp = data.get('otp')

    temp_data = session.get('temp_registration')
    if not temp_data:
        return jsonify({'success': False, 'message': 'Session expired'})

    reg_type = temp_data['type']
    reg_data = temp_data['data']
    email = reg_data['email']

    if verify_otp(email, otp, f"{reg_type.upper()}_REGISTRATION"):
        if reg_type == 'hospital':
            state_code = Config.STATE_CODES.get(reg_data['state'], 'XX')
            hospital_id = generate_unique_id('HOS', state_code)

            hospital = Hospital(
                hospital_id=hospital_id,
                hospital_name=reg_data['name'],
                license_number=reg_data['license'],
                address=reg_data.get('address', ''),
                state=reg_data['state'],
                admin_email=email,
                admin_mobile=reg_data['mobile'],
                password_hash=Hospital.hash_password(reg_data['password'])
            )

            db.session.add(hospital)

            approval = ApprovalQueue(
                request_type='HOSPITAL_REGISTRATION',
                request_data=json.dumps({'hospital_id': hospital_id}),
                hospital_id=hospital_id,
                requested_by=email
            )

            db.session.add(approval)
            db.session.commit()

            session.pop('temp_registration', None)

            return jsonify({
                'success': True,
                'message': f'✅ Registration successful! Hospital ID: {hospital_id}. Awaiting admin approval.',
                'redirect': url_for('index')
            })

        elif reg_type == 'patient':
            patient_id = generate_unique_id('PAT-IN')

            patient = Patient(
                patient_id=patient_id,
                full_name=reg_data['name'],
                email=email,
                mobile=reg_data['mobile'],
                dob=datetime.strptime(reg_data['dob'], '%Y-%m-%d').date(),
                gender=reg_data['gender'],
                blood_group=reg_data.get('blood_group', ''),
                password_hash=Patient.hash_password(reg_data['password'])
            )

            db.session.add(patient)
            db.session.commit()

            session.pop('temp_registration', None)

            return jsonify({
                'success': True,
                'message': f'✅ Registration successful! Your Patient ID: {patient_id}',
                'redirect': url_for('login', user_type='Patient')
            })

    return jsonify({'success': False, 'message': 'Invalid OTP'})


@app.route('/dashboard')
@login_required
def dashboard():
    user_type = session.get('user_type')

    if user_type == 'Super Admin':
        pending_approvals = ApprovalQueue.query.filter_by(status='PENDING').all()
        active_hospitals = Hospital.query.filter_by(is_active=True).count()
        total_patients = Patient.query.count()
        pending_count = len(pending_approvals)

        return render_template_string(
            DASHBOARD_SUPER_ADMIN_HTML,
            pending_approvals=pending_approvals,
            active_hospitals=active_hospitals,
            total_patients=total_patients,
            pending_count=pending_count
        )

    elif user_type == 'Hospital':
        # --- NEW LOGIC START ---
        # 1. Fetch Key Statistics
        staff_count = HospitalStaff.query.filter_by(hospital_id=current_user.hospital_id).count()
        dept_count = Department.query.filter_by(hospital_id=current_user.hospital_id).count()
        admitted_count = PatientAdmission.query.filter_by(hospital_id=current_user.hospital_id,
                                                          status='ADMITTED').count()

        # Calculate Prescriptions generated today
        today_start = datetime.combine(date.today(), datetime.min.time())
        today_rx = Prescription.query.filter(
            Prescription.hospital_id == current_user.hospital_id,
            Prescription.created_at >= today_start
        ).count()

        stats = {
            'staff_count': staff_count,
            'dept_count': dept_count,
            'admitted_count': admitted_count,
            'today_rx': today_rx
        }

        # 2. Fetch Recent Admissions for the Table
        raw_admissions = PatientAdmission.query.filter_by(
            hospital_id=current_user.hospital_id,
            status='ADMITTED'
        ).order_by(PatientAdmission.admission_date.desc()).limit(5).all()

        recent_admissions = []
        for adm in raw_admissions:
            patient = Patient.query.get(adm.patient_id)
            doctor = HospitalStaff.query.get(adm.doctor_id)
            recent_admissions.append({
                'admission_id': adm.admission_id,
                'patient_name': patient.full_name if patient else 'Unknown',
                'doctor_name': doctor.last_name if doctor else 'Unknown',
                'room_number': adm.room_number,
                'admission_date': adm.admission_date
            })

        return render_template_string(
            DASHBOARD_HOSPITAL_HTML,
            hospital=current_user,
            stats=stats,
            recent_admissions=recent_admissions
        )
        # --- NEW LOGIC END ---

    elif user_type == 'Staff':
        if current_user.role == 'DOCTOR':
            return doctor_dashboard()
        else:
            return f"<h1>Welcome {current_user.role.title()} {current_user.last_name}</h1><p>Dashboard under construction for this role.</p><a href='/logout'>Logout</a>"

    elif user_type == 'Patient':
        # Lifecycle management - Show Prescriptions
        my_prescriptions = Prescription.query.filter_by(patient_id=current_user.patient_id).all()

        # Inject prescriptions into the dashboard HTML
        rx_html = "<h3>My Prescriptions</h3><ul>"
        if my_prescriptions:
            for rx in my_prescriptions:
                rx_html += f"<li><strong>{rx.created_at.strftime('%Y-%m-%d')}</strong>: {rx.diagnosis} (ID: {rx.prescription_id})</li>"
        else:
            rx_html += "<li>No prescriptions found.</li>"
        rx_html += "</ul>"

        updated_html = DASHBOARD_PATIENT_HTML.replace('</div>\n</body>', f'{rx_html}</div></body>')
        return render_template_string(updated_html, patient=current_user)

    elif user_type == 'Guest':
        hospitals = Hospital.query.filter_by(is_active=True).all()
        return render_template_string(DASHBOARD_GUEST_HTML, hospitals=hospitals)

    return redirect(url_for('index'))


@app.route('/admin/approve/<int:approval_id>', methods=['POST'])
@login_required
def approve_hospital(approval_id):
    if session.get('user_type') != 'Super Admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})

    approval = ApprovalQueue.query.get_or_404(approval_id)
    hospital = Hospital.query.get(approval.hospital_id)

    if hospital:
        hospital.approval_status = 'APPROVED'
        hospital.is_active = True
        hospital.approved_by = current_user.admin_id
        hospital.approved_date = datetime.utcnow()

        approval.status = 'APPROVED'
        approval.reviewed_by = current_user.admin_id
        approval.reviewed_date = datetime.utcnow()

        hospital.database_schema = f"hospital_{hospital.hospital_id.replace('-', '_')}.db"

        db.session.commit()

        return jsonify({'success': True, 'message': 'Hospital approved successfully!'})

    return jsonify({'success': False, 'message': 'Hospital not found'})


@app.route('/admin/reject/<int:approval_id>', methods=['POST'])
@login_required
def reject_hospital(approval_id):
    if session.get('user_type') != 'Super Admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})

    data = request.get_json()
    reason = data.get('reason', 'No reason provided')

    approval = ApprovalQueue.query.get_or_404(approval_id)
    hospital = Hospital.query.get(approval.hospital_id)

    if hospital:
        hospital.approval_status = 'REJECTED'

        approval.status = 'REJECTED'
        approval.reviewed_by = current_user.admin_id
        approval.reviewed_date = datetime.utcnow()
        approval.comments = reason

        db.session.commit()

        return jsonify({'success': True, 'message': 'Hospital application rejected'})

    return jsonify({'success': False, 'message': 'Hospital not found'})


# --- HOSPITAL ADMIN: MANAGE STAFF ROUTES ---
@app.route('/hospital/staff')
@login_required
def hospital_manage_staff():
    if session.get('user_type') != 'Hospital':
        return "Unauthorized", 403

    staff_members = HospitalStaff.query.filter_by(hospital_id=current_user.hospital_id).all()
    return render_template_string(HOSPITAL_MANAGE_STAFF_HTML, staff_members=staff_members)


@app.route('/hospital/add-staff', methods=['POST'])
@login_required
def hospital_add_staff():
    if session.get('user_type') != 'Hospital':
        return "Unauthorized", 403

    # Generate Staff ID: {HospitalID}-STF-{Random}
    staff_id = f"{current_user.hospital_id}-STF-{secrets.token_hex(2).upper()}"

    new_staff = HospitalStaff(
        staff_id=staff_id,
        hospital_id=current_user.hospital_id,
        first_name=request.form.get('first_name'),
        last_name=request.form.get('last_name'),
        email=request.form.get('email'),
        role=request.form.get('role'),
        department=request.form.get('department'),
        password_hash=hashlib.sha256(request.form.get('password').encode()).hexdigest()
    )

    db.session.add(new_staff)
    db.session.commit()
    return redirect(url_for('hospital_manage_staff'))


# ============================================================================
# HOSPITAL MANAGEMENT ROUTES (Departments & Admissions)
# ============================================================================

@app.route('/hospital/departments')
@login_required
def hospital_departments():
    if session.get('user_type') != 'Hospital':
        return "Unauthorized", 403

    departments = Department.query.filter_by(hospital_id=current_user.hospital_id).all()
    return render_template_string(HOSPITAL_DEPARTMENTS_HTML, departments=departments)


@app.route('/hospital/add-department', methods=['POST'])
@login_required
def add_department():
    if session.get('user_type') != 'Hospital':
        return "Unauthorized", 403

    name = request.form.get('name')
    if name:
        dept = Department(hospital_id=current_user.hospital_id, name=name)
        db.session.add(dept)
        db.session.commit()
    return redirect(url_for('hospital_departments'))


@app.route('/hospital/admissions')
@login_required
def hospital_admissions():
    if session.get('user_type') != 'Hospital':
        return "Unauthorized", 403

    # In a production app, use AJAX search. Listing all for Hackathon simplicity.
    all_patients = Patient.query.all()
    doctors = HospitalStaff.query.filter_by(hospital_id=current_user.hospital_id, role='DOCTOR').all()

    return render_template_string(HOSPITAL_ADMISSIONS_HTML, patients=all_patients, doctors=doctors)


@app.route('/hospital/admit-patient', methods=['POST'])
@login_required
def admit_patient():
    if session.get('user_type') != 'Hospital':
        return "Unauthorized", 403

    admission = PatientAdmission(
        hospital_id=current_user.hospital_id,
        patient_id=request.form.get('patient_id'),
        doctor_id=request.form.get('doctor_id'),
        room_number=request.form.get('room_number'),
        reason=request.form.get('reason'),
        status='ADMITTED'
    )
    db.session.add(admission)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/hospital/discharge/<int:admission_id>')
@login_required
def discharge_patient(admission_id):
    if session.get('user_type') != 'Hospital':
        return "Unauthorized", 403

    admission = PatientAdmission.query.get_or_404(admission_id)

    # Security Check: Ensure hospital owns this admission record
    if admission.hospital_id != current_user.hospital_id:
        return "Unauthorized", 403

    admission.status = 'DISCHARGED'
    admission.discharge_date = datetime.utcnow()
    db.session.commit()
    return redirect(url_for('dashboard'))


# --- DOCTOR ROUTES ---
@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if session.get('user_type') != 'Staff' or current_user.role != 'DOCTOR':
        return "Unauthorized Access", 403

    hospital = Hospital.query.get(current_user.hospital_id)
    return render_template_string(DOCTOR_DASHBOARD_HTML, user=current_user, hospital_name=hospital.hospital_name,
                                  patient=None)


@app.route('/doctor/search-patient', methods=['POST'])
@login_required
def doctor_search_patient():
    term = request.form.get('search_term')

    # Search by ID, Phone, or Name
    patient = Patient.query.filter(
        (Patient.patient_id == term) |
        (Patient.mobile == term) |
        (Patient.full_name.ilike(f"%{term}%"))
    ).first()

    hospital = Hospital.query.get(current_user.hospital_id)
    return render_template_string(DOCTOR_DASHBOARD_HTML, user=current_user, hospital_name=hospital.hospital_name,
                                  patient=patient)


@app.route('/doctor/create-prescription', methods=['POST'])
@login_required
def create_prescription():
    if current_user.role != 'DOCTOR':
        return "Unauthorized", 403

    patient_id = request.form.get('patient_id')
    diagnosis = request.form.get('diagnosis')

    # Process Medicines List
    med_names = request.form.getlist('med_name[]')
    med_dosages = request.form.getlist('med_dosage[]')
    med_durations = request.form.getlist('med_duration[]')

    medicines = []
    for i in range(len(med_names)):
        medicines.append({
            'name': med_names[i],
            'dosage': med_dosages[i],
            'duration': med_durations[i]
        })

    # Generate Prescription ID
    rx_id = f"{current_user.hospital_id}-RX-{secrets.token_hex(4).upper()}"

    rx = Prescription(
        prescription_id=rx_id,
        hospital_id=current_user.hospital_id,
        doctor_id=current_user.staff_id,
        patient_id=patient_id,
        diagnosis=diagnosis,
        medicines=json.dumps(medicines)
    )

    db.session.add(rx)
    db.session.commit()

    return f"<h1>✅ Prescription Created Successfully!</h1><p>ID: {rx_id}</p><a href='/dashboard'>Back to Dashboard</a>"


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))


# ============================================================================
# INITIALIZE DATABASE
# ============================================================================

def init_database():
    with app.app_context():
        db.create_all()

        if not SuperAdmin.query.filter_by(username='admin').first():
            admin = SuperAdmin(
                admin_id='ADMIN-MASTER-001',
                username='admin',
                email='admin@medicloud.com',
                password_hash=SuperAdmin.hash_password('Admin@123')
            )
            db.session.add(admin)
            db.session.commit()
            print("\n✅ Default Super Admin created:")
            print("   Email: admin@medicloud.com")
            print("   Password: Admin@123\n")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("MEDICLOUD - HOSPITAL MANAGEMENT SYSTEM")
    print("=" * 60)
    print("\n⚙️  Initializing database...")

    init_database()

    print("\n📧  Gmail SMTP Configuration:")
    print(f"   Email: {app.config['MAIL_USERNAME']}")
    print("   ⚠️  Update email credentials in code for OTP functionality!\n")

    print("🚀  Starting Flask application...")
    print("   Access: http://localhost:5000")
    print("   Super Admin: admin@medicloud.com / Admin@123\n")
    print("=" * 60 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5000)