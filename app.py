from flask import Flask, redirect, render_template, request, url_for,session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, bcrypt
import os
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir, 'database.db')
app.secret_key = 'your_secret_key'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt=Bcrypt(app)
class data(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'Name:{self.username}'

#FOLLOWING CODE CAN BE RUN ONCE TO CREATE THE DATABASE
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
@app.route('/')
def re():
    return redirect(url_for('index'))
@app.route('/index',methods=['GET','POST'])
def index():
    if request.method=='POST':
        email=request.form.get("email")
        existing_user = data.query.filter_by(email=email).first()
        if not existing_user:
            return render_template('index.html',error='User does not exists')
        session['logged_in']=True
        return redirect(url_for('success'))
    return render_template("index.html")

@app.route('/sign-up',methods=['GET','POST'])
def signup():
    if request.method=='POST':
        email=request.form.get("email")
        name=request.form.get("username")
        password=request.form.get("password")

        #validation
        existing_email = data.query.filter_by(email=email).first()
        existing_name = data.query.filter_by(username=name).first()
        if existing_email:
            return render_template('signup.html',error='This email is already in use')
        if existing_name:
            return render_template('signup.html',error='Username is already taken')
        new_user=data(username=name,email=email,password=bcrypt.generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return render_template("signup.html",msg="User registered successfully")    

    return render_template("signup.html")

@app.route('/success')
def success():
    if session.get('logged_in',None) is None:
        return redirect(url_for('index'))
    return render_template('success.html')


