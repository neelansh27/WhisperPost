from flask import Flask, redirect, render_template, request, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_bcrypt import Bcrypt, bcrypt
from flask_login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin
import os
from pytz import timezone
from datetime import datetime

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
        return f'Email:{self.email}'


class posts(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    author = db.Column(db.String(40), nullable=False)
    title = db.Column(db.String(40), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(
        timezone('Asia/Kolkata')))
# .strftime("%Y-%m-%d %I:%M:%S%p %Z%z") format to display

    def __repr__(self):
        return f"author:{self.author}, \
                 title:{self.title}, \
                 content:{self.content}, \
                 time:{self.created_at} "


# FOLLOWING CODE CAN BE RUN ONCE TO CREATE THE DATABASE
# if __name__ == "__main__":
#     with app.app_context():
#         db.create_all()

# This piece of code here is very important and big shoutout to the stack overflow guy who gave this solution: https://stackoverflow.com/questions/20652784/flask-back-button-returns-to-session-even-after-logout
# It prevents browser cache and prevent user from going back and forth between login and home page
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route('/')  # redirecting root to a different page
def re():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get('password')
        user = data.query.filter_by(email=email).first()
        if not user:  # checking if user exists of not
            return render_template('login.html', error='User does not exists')
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
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


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():

    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        # all_posts = posts.query.paginate(page=page, per_page=6)
        all_posts=db.paginate(posts.query.order_by(desc('created_at')),page=page,per_page=5)
        return render_template('home.html', current_user=current_user, posts=all_posts,page=page)

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content').strip()
        author = current_user.username
        time = datetime.now(timezone('Asia/Kolkata'))
        post = posts(title=title, content=content,
                     author=author, created_at=time)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('success'))


@app.route('/success')
@login_required
def success():
    return redirect(url_for('home'))
