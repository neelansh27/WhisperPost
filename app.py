from flask import Flask, redirect, render_template, request, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, bcrypt
from flask_login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin
import os

from sqlalchemy.engine import url
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'database.db')
app.secret_key = 'your_secret_key'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # reffering to login page


@login_manager.user_loader
def load_user(user_id):
    return data.query.get(int(user_id))


class data(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'Name:{self.username}'

# FOLLOWING CODE CAN BE RUN ONCE TO CREATE THE DATABASE
# if __name__ == "__main__":
#     with app.app_context():
#         db.create_all()


@app.route('/')  # redirecting root to a different page
def re():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('success'))
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get('password')
        user = data.query.filter_by(email=email).first()
        if not user:  # checking if user exists of not
            return render_template('login.html', error='User does not exists')
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('success'))
        else:
            return render_template('login.html', error='Incorrect password')
    return render_template("login.html")


@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get("email")
        name = request.form.get("username")
        password = request.form.get("password")

        # validation
        existing_email = data.query.filter_by(email=email).first()
        existing_name = data.query.filter_by(username=name).first()
        if existing_email:
            return render_template('signup.html', error='This email is already in use')
        if existing_name:
            return render_template('signup.html', error='Username is already taken')
        new_user = data(username=name, email=email,
                        password=bcrypt.generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return render_template("signup.html", msg="User registered successfully")

    return render_template("signup.html")


@app.route('/success')
@login_required
def success():
    return render_template('success.html', user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
