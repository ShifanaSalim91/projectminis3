# app.py
import os
import threading
import time
from datetime import datetime, date, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from twilio.rest import Client
import smtplib
from email.mime.text import MIMEText

load_dotenv()  # load .env if present

# Sample WHO reference for boys/girls, 0-15 years (height in cm, weight in kg)
# For real use, expand these lists to 180 values (months 0-180)
WHO_HEIGHT_BOYS = [49.9, 54.7, 58.4, 61.4, 63.9, 65.9, 67.6, 69.2, 70.6, 72.0, 73.3, 74.5, 75.7, 76.9, 78.0, 79.2]
WHO_WEIGHT_BOYS = [3.3, 4.5, 5.6, 6.4, 7.0, 7.5, 7.9, 8.3, 8.6, 8.9, 9.2, 9.4, 9.6, 9.8, 10.0, 10.2]

WHO_HEIGHT_GIRLS = [49.1, 53.7, 57.1, 59.8, 62.1, 64.0, 65.7, 67.3, 68.7, 70.1, 71.5, 72.8, 74.0, 75.2, 76.4, 77.5]
WHO_WEIGHT_GIRLS = [3.2, 4.2, 5.1, 5.8, 6.4, 6.9, 7.3, 7.6, 7.9, 8.2, 8.5, 8.7, 8.9, 9.2, 9.4, 9.6]
# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'change_this_secret')
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'vaccine.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------- MODELS ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(200), nullable=False)
    children = db.relationship('Child', backref='parent', lazy=True)

class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(20))
    profile_pic = db.Column(db.String(200))
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vaccination_records = db.relationship('VaccinationRecord', backref='child', lazy=True)

class Vaccine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    dose_number = db.Column(db.String(50), nullable=False)

class VaccinationRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'), nullable=False)
    vaccine_id = db.Column(db.Integer, db.ForeignKey('vaccine.id'), nullable=False)
    dose_number = db.Column(db.String(50))
    due_date = db.Column(db.Date)
    date_taken = db.Column(db.Date)
    reminded_week = db.Column(db.Boolean, default=False)      # 7 days before
    reminded_two_day = db.Column(db.Boolean, default=False)   # 2 days before
    vaccine = db.relationship('Vaccine')

class GrowthRecord(db.Model):
    growth_id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    height_cm = db.Column(db.Float, nullable=True)
    weight_kg = db.Column(db.Float, nullable=True)
    child = db.relationship('Child')

    

# ---------------- LOGIN ----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- INDIAN VACCINE SCHEDULE (days from DOB) ----------------
# (birth -> 15 years roughly)
VACCINE_SCHEDULE = [
    {"name": "BCG", "dose": "1", "days": 0},
    {"name": "OPV", "dose": "0", "days": 0},
    {"name": "Hepatitis B", "dose": "0", "days": 0},

    {"name": "DPT", "dose": "1", "days": 42}, {"name": "OPV", "dose": "1", "days": 42},
    {"name": "Hepatitis B", "dose": "1", "days": 42}, {"name": "Hib", "dose": "1", "days": 42},
    {"name": "PCV", "dose": "1", "days": 42}, {"name": "Rotavirus", "dose": "1", "days": 42},

    {"name": "DPT", "dose": "2", "days": 70}, {"name": "OPV", "dose": "2", "days": 70},
    {"name": "Hib", "dose": "2", "days": 70}, {"name": "PCV", "dose": "2", "days": 70},
    {"name": "Rotavirus", "dose": "2", "days": 70},

    {"name": "DPT", "dose": "3", "days": 98}, {"name": "OPV", "dose": "3", "days": 98},
    {"name": "Hib", "dose": "3", "days": 98}, {"name": "PCV", "dose": "3", "days": 98},
    {"name": "Rotavirus", "dose": "3", "days": 98}, {"name": "Hepatitis B", "dose": "2", "days": 98},

    {"name": "Influenza", "dose": "1", "days": 183}, {"name": "Influenza", "dose": "2", "days": 213},
    {"name": "MMR", "dose": "1", "days": 274}, {"name": "JE", "dose": "1", "days": 274},
    {"name": "Hepatitis A", "dose": "1", "days": 365},

    {"name": "MMR", "dose": "2", "days": 456}, {"name": "Varicella", "dose": "1", "days": 456},
    {"name": "PCV", "dose": "Booster", "days": 456},

    {"name": "DPT", "dose": "Booster1", "days": 487}, {"name": "OPV", "dose": "Booster1", "days": 487},
    {"name": "Hib", "dose": "Booster", "days": 487},

    {"name": "Hepatitis A", "dose": "2", "days": 548}, {"name": "Typhoid Conjugate", "dose": "1", "days": 730},

    {"name": "DPT", "dose": "Booster2", "days": 1825}, {"name": "OPV", "dose": "Booster2", "days": 1825},
    {"name": "Varicella", "dose": "2", "days": 1825}, {"name": "Typhoid", "dose": "Booster", "days": 1825},

    {"name": "HPV", "dose": "1", "days": 3285}, {"name": "HPV", "dose": "2", "days": 3465},
    {"name": "Tdap/Td", "dose": "1", "days": 3650}, {"name": "JE", "dose": "2", "days": 3650},

    {"name": "Typhoid", "dose": "Booster (15y)", "days": 5475}, {"name": "MMR", "dose": "3", "days": 5475},
]

# ---------------- HELPERS ----------------
def compute_due(dob, days):
    return dob + timedelta(days=days)

def vaccine_status(record):
    today = date.today()
    if record.date_taken:
        return 'completed'
    if record.due_date and record.due_date < today:
        return 'missed'
    return 'upcoming'

# ---------------- ROUTES ----------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        phone = request.form.get('phone','').strip()
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger"); return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger"); return redirect(url_for('register'))
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        u = User(username=username, email=email, phone=phone, password=hashed)
        db.session.add(u); db.session.commit()
        flash("Registered — please login", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# ...existing code...

def reminder_worker():
    WAIT_SECONDS = 60 * 60  # hourly
    while True:
        with app.app_context():
            today = date.today()
            week_threshold = today + timedelta(days=7)
            two_day_threshold = today + timedelta(days=2)
            records = VaccinationRecord.query.filter(VaccinationRecord.date_taken.is_(None)).all()
            for r in records:
                parent = r.child.parent
                # 7 days before
                if r.due_date == week_threshold and not r.reminded_week:
                    msg = f"Reminder: {r.child.name} is due for {r.vaccine.name} (dose {r.dose_number}) in one week on {r.due_date.strftime('%Y-%m-%d')}."
                    if parent.phone:
                        try: send_sms(parent.phone, msg)
                        except: app.logger.exception("sms error")
                    if parent.email:
                        try: send_email(parent.email, f"Vaccine reminder for {r.child.name}", msg)
                        except: app.logger.exception("email error")
                    r.reminded_week = True
                    db.session.commit()
                # 2 days before
                if r.due_date == two_day_threshold and not r.reminded_two_day:
                    msg = f"Urgent: {r.child.name} is due for {r.vaccine.name} (dose {r.dose_number}) in two days on {r.due_date.strftime('%Y-%m-%d')}."
                    if parent.phone:
                        try: send_sms(parent.phone, msg)
                        except: app.logger.exception("sms error")
                    if parent.email:
                        try: send_email(parent.email, f"Vaccine reminder for {r.child.name}", msg)
                        except: app.logger.exception("email error")
                    r.reminded_two_day = True
                    db.session.commit()
        time.sleep(WAIT_SECONDS)
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user); return redirect(url_for('dashboard'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')

from flask import render_template, request, redirect, url_for, flash
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash
from flask_mail import Mail, Message

# Setup serializer for tokens
s = URLSafeTimedSerializer(app.secret_key)

# Flask-Mail config (update with your email server settings)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "your_email@gmail.com"
app.config['MAIL_PASSWORD'] = "your_app_password"
mail = Mail(app)

# Forgot Password
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)

            # Send email
            msg = Message('Password Reset - Smart Childcare',
                          sender="your_email@gmail.com",
                          recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_link}"
            mail.send(msg)

            flash('Password reset link sent to your email!', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email.', 'danger')
    return render_template('forgot_password.html')

# Reset Password
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=1800)  # 30 mins
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match!', 'danger')
        else:
            user = User.query.filter_by(email=email).first()
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your password has been reset. Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/add_growth/<int:child_id>', methods=['GET', 'POST'])
@login_required
def add_growth(child_id):
    child = Child.query.get_or_404(child_id)
    if request.method == 'POST':
        date_str = request.form['date']
        height = request.form.get('height_cm')
        weight = request.form.get('weight_kg')
        try:
            date_val = datetime.strptime(date_str, '%Y-%m-%d').date()
            height_val = float(height) if height else None
            weight_val = float(weight) if weight else None
            rec = GrowthRecord(child_id=child.id, date=date_val, height_cm=height_val, weight_kg=weight_val)
            db.session.add(rec); db.session.commit()
            flash("Growth record added", "success")
            return redirect(url_for('view_child', child_id=child.id))
        except:
            flash("Invalid input", "danger")
    return render_template('add_growth.html', child=child)


@app.route('/logout')
@login_required
def logout():
    logout_user(); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', children=current_user.children)

@app.route('/add_child', methods=['GET','POST'])
@login_required
def add_child():
    if request.method=='POST':
        name = request.form['name'].strip()
        dob_str = request.form['dob'].strip()
        gender = request.form.get('gender','').strip()
        try:
            dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except:
            flash("Invalid date format", "danger"); return redirect(url_for('add_child'))
        # profile pic
        profile_pic = None
        if 'profile_pic' in request.files:
            f = request.files['profile_pic']
            if f and f.filename:
                fname = secure_filename(f.filename)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
                profile_pic = fname
        child = Child(name=name, dob=dob, gender=gender, profile_pic=profile_pic, parent_id=current_user.id)
        db.session.add(child); db.session.commit()
        # create vaccination records with due_date
        for v in VACCINE_SCHEDULE:
            vaccine = Vaccine.query.filter_by(name=v['name'], dose_number=str(v['dose'])).first()
            if not vaccine:
                vaccine = Vaccine(name=v['name'], dose_number=str(v['dose']))
                db.session.add(vaccine); db.session.commit()
            due = compute_due(dob, v['days'])
            rec = VaccinationRecord(child_id=child.id, vaccine_id=vaccine.id, dose_number=str(v['dose']), due_date=due)
            db.session.add(rec)
        db.session.commit()
        flash("Child added and vaccine schedule created", "success")
        return redirect(url_for('dashboard'))
    return render_template('add_child.html')

from io import StringIO
import csv
from flask import make_response

@app.route('/download_vaccine_report/<int:record_id>')
@login_required
def download_vaccine_report(record_id):
    record = VaccinationRecord.query.get_or_404(record_id)
    child = record.child
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Child Name', 'Vaccine', 'Dose', 'Due Date', 'Date Taken', 'Status'])
    status = 'Completed' if record.date_taken else ('Missed' if record.due_date and record.due_date < date.today() else 'Upcoming')
    writer.writerow([
        child.name,
        record.vaccine.name,
        record.dose_number,
        record.due_date.strftime('%Y-%m-%d') if record.due_date else '',
        record.date_taken.strftime('%Y-%m-%d') if record.date_taken else '',
        status
    ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={child.name}_{record.vaccine.name}_dose{record.dose_number}_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

from datetime import date

@app.route("/child/<int:child_id>")
@login_required
def view_child(child_id):
    child = Child.query.get_or_404(child_id)
    growth_records = GrowthRecord.query.filter_by(child_id=child.id).order_by(GrowthRecord.date).all()
    # ...existing vaccine grouping...
    grouped_records = {}
    for record in child.vaccination_records:
        recommended_age_days = (record.due_date - child.dob).days if record.due_date else 0

        if recommended_age_days <= 7:
            age_group = "Birth"
        elif recommended_age_days <= 42:
            age_group = "6 weeks"
        elif recommended_age_days <= 70:
            age_group = "10 weeks"
        elif recommended_age_days <= 98:
            age_group = "14 weeks"
        elif recommended_age_days <= 183:
            age_group = "6 months"
        elif recommended_age_days <= 365:
            age_group = "1 year"
        else:
            age_group = f"{recommended_age_days//365} yr {((recommended_age_days%365)//30)} mo"

        grouped_records.setdefault(age_group, {})
        grouped_records[age_group].setdefault(record.vaccine.name, [])
        grouped_records[age_group][record.vaccine.name].append(record)  # <-- pass the object itself

    return render_template(
        "child.html",
        child=child,
        grouped_records=grouped_records,
        growth_records=growth_records,
        current_date=date.today()
    )

def assess_growth(child, growth_records):
    # Select reference table based on gender
    if child.gender and child.gender.lower().startswith('f'):
        ref_height = WHO_HEIGHT_GIRLS
        ref_weight = WHO_WEIGHT_GIRLS
    else:
        ref_height = WHO_HEIGHT_BOYS
        ref_weight = WHO_WEIGHT_BOYS

    status = "Growth is tracking well according to WHO standards."
    for rec in growth_records:
        months = (rec.date.year - child.dob.year) * 12 + (rec.date.month - child.dob.month)
        if months < len(ref_height):
            if rec.height_cm and rec.height_cm < ref_height[months] - 2:
                return "Height is below WHO recommended range for age. Please consult a pediatrician."
            if rec.weight_kg and rec.weight_kg < ref_weight[months] - 0.5:
                return "Weight is below WHO recommended range for age. Please consult a pediatrician."
    return status
from datetime import datetime

@app.route('/edit_child/<int:child_id>', methods=['GET', 'POST'])
def edit_child(child_id):
    child = Child.query.get_or_404(child_id)

    if request.method == 'POST':
        child.name = request.form['name']
        child.gender = request.form['gender']

        # Convert string to date
        dob_str = request.form['dob']  # e.g., '2025-06-03'
        child.dob = datetime.strptime(dob_str, '%Y-%m-%d').date()

        # Optional: handle profile picture update
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                child.profile_pic = filename

        db.session.commit()
        flash('Child profile updated successfully!', 'success')
        return redirect(url_for('view_child', child_id=child.id))

    return render_template('edit_child.html', child=child)


@app.route('/delete_child/<int:child_id>')
@login_required
def delete_child(child_id):
    child = Child.query.get_or_404(child_id)
    if child.parent_id != current_user.id:
        flash("Not authorized", "danger"); return redirect(url_for('dashboard'))
    VaccinationRecord.query.filter_by(child_id=child.id).delete()
    db.session.delete(child)
    db.session.commit()
    flash("Child deleted", "success")
    return redirect(url_for('dashboard'))
@app.route('/mark_completed/<int:record_id>')
@login_required
def mark_completed(record_id):
    rec = VaccinationRecord.query.get_or_404(record_id)
    if rec.child.parent_id != current_user.id:
        flash("Not authorized", "danger")
        return redirect(url_for('dashboard'))

    # 🚫 Prevent marking before due date
    if rec.due_date and rec.due_date > date.today():
        flash("This vaccine is not due yet!", "warning")
        return redirect(url_for('view_child', child_id=rec.child_id))

    rec.date_taken = date.today()
    db.session.commit()
    flash("Marked completed", "success")
    return redirect(url_for('view_child', child_id=rec.child_id))


@app.route('/add_vaccine/<int:child_id>', methods=['POST'])
@login_required
def add_vaccine(child_id):
    child = Child.query.get_or_404(child_id)
    if child.parent_id != current_user.id:
        flash("Not authorized", "danger"); return redirect(url_for('dashboard'))
    vname = request.form['vaccine_name'].strip()
    vdose = request.form['vaccine_dose'].strip()
    due_str = request.form.get('due_date','').strip()
    taken_str = request.form.get('date_taken','').strip()
    due = None
    taken = None
    try:
        if due_str:
            due = datetime.strptime(due_str, '%Y-%m-%d').date()
        if taken_str:
            taken = datetime.strptime(taken_str, '%Y-%m-%d').date()
    except:
        flash("Invalid date format", "warning")
    vaccine = Vaccine.query.filter_by(name=vname, dose_number=vdose).first()
    if not vaccine:
        vaccine = Vaccine(name=vname, dose_number=vdose)
        db.session.add(vaccine); db.session.commit()
    rec = VaccinationRecord(child_id=child.id, vaccine_id=vaccine.id, dose_number=vdose, due_date=due, date_taken=taken)
    db.session.add(rec); db.session.commit()
    flash("Vaccine added", "success")
    return redirect(url_for('view_child', child_id=child.id))

# ---------------- REMINDERS (background) ----------------
def send_sms(to_number, body):
    sid = os.getenv('TWILIO_SID'); token = os.getenv('TWILIO_TOKEN'); tw_from = os.getenv('TWILIO_FROM')
    if not (sid and token and tw_from):
        app.logger.debug("Twilio not configured; SMS skipped.")
        return
    try:
        client = Client(sid, token)
        client.messages.create(body=body, from_=tw_from, to=to_number)
    except Exception as e:
        app.logger.exception("Twilio send failed")

def send_email(to_email, subject, body):
    user = os.getenv('EMAIL_USER'); pwd = os.getenv('EMAIL_PASS')
    if not (user and pwd):
        app.logger.debug("Email not configured; email skipped.")
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject; msg['From'] = user; msg['To'] = to_email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(user, pwd)
            s.sendmail(user, [to_email], msg.as_string())
    except Exception:
        app.logger.exception("Email send failed")

@app.route('/growth_history/<int:child_id>')
@login_required
def growth_history(child_id):
    child = Child.query.get_or_404(child_id)
    growth_records = GrowthRecord.query.filter_by(child_id=child.id).order_by(GrowthRecord.date).all()
    status = assess_growth(child, growth_records)
    return render_template('growth_history.html', child=child, growth_records=growth_records, status=status)
def reminder_worker():
    WAIT_SECONDS = 60 * 60  # hourly
    while True:
        with app.app_context():
            today = date.today()
            week_threshold = today + timedelta(days=7)
            two_day_threshold = today + timedelta(days=2)
            records = VaccinationRecord.query.filter(VaccinationRecord.date_taken.is_(None)).all()
            for r in records:
                parent = r.child.parent
                # 7 days before
                if r.due_date == week_threshold and not r.reminded_week:
                    msg = f"Reminder: {r.child.name} is due for {r.vaccine.name} (dose {r.dose_number}) in one week on {r.due_date.strftime('%Y-%m-%d')}."
                    if parent.phone:
                        try: send_sms(parent.phone, msg)
                        except: app.logger.exception("sms error")
                    if parent.email:
                        try: send_email(parent.email, f"Vaccine reminder for {r.child.name}", msg)
                        except: app.logger.exception("email error")
                    r.reminded_week = True
                    db.session.commit()
                # 2 days before
                if r.due_date == two_day_threshold and not r.reminded_two_day:
                    msg = f"Urgent: {r.child.name} is due for {r.vaccine.name} (dose {r.dose_number}) in two days on {r.due_date.strftime('%Y-%m-%d')}."
                    if parent.phone:
                        try: send_sms(parent.phone, msg)
                        except: app.logger.exception("sms error")
                    if parent.email:
                        try: send_email(parent.email, f"Vaccine reminder for {r.child.name}", msg)
                        except: app.logger.exception("email error")
                    r.reminded_two_day = True
                    db.session.commit()
        time.sleep(WAIT_SECONDS)

def growth_reminder_worker():
    WAIT_SECONDS = 60 * 60 * 24  # daily
    while True:
        with app.app_context():
            today = date.today()
            for child in Child.query.all():
                latest = GrowthRecord.query.filter_by(child_id=child.id).order_by(GrowthRecord.date.desc()).first()
                if not latest or latest.date.month != today.month or latest.date.year != today.year:
                    parent = child.parent
                    msg = f"Reminder: Please enter {child.name}'s height and weight for {today.strftime('%B %Y')}."
                    if parent.phone:
                        try: send_sms(parent.phone, msg)
                        except: app.logger.exception("sms error")
                    if parent.email:
                        try: send_email(parent.email, f"Growth reminder for {child.name}", msg)
                        except: app.logger.exception("email error")
        time.sleep(WAIT_SECONDS)

# In your main section, start the thread:
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    threading.Thread(target=reminder_worker, daemon=True).start()
    threading.Thread(target=growth_reminder_worker, daemon=True).start()
    app.run(debug=True)