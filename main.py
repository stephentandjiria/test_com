from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from is_safe_url import is_safe_url

import os

app = Flask(__name__)

# app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# Offer Alternative: app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///users.db")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    logged_in = current_user.is_authenticated
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name_input = request.form["name"]
        email_input = request.form["email"]
        password_input = request.form["password"]
        if User.query.filter_by(email=email_input).first():
            flash('Email is taken', 'error')
            return redirect(url_for('register', logged_in=current_user.is_authenticated))
        else:
            hashed_password = generate_password_hash(password_input, "pbkdf2:sha256", 8)
            new_user = User(name=name_input, email=email_input, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('secrets', name=name_input))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email_input = request.form["email"]
        user = User.query.filter_by(email=email_input).first()
        if user:
            password_input = request.form["password"]
            password_is_correct = check_password_hash(user.password, password_input)
            if password_is_correct:
                # Login and validate the user.
                # user should be an instance of your `User` class
                login_user(user)
                flash('Logged in successfully.', 'login_success')
                return redirect(url_for('secrets', name=user.name, logged_in=current_user.is_authenticated))
            else:
                flash('Wrong password', 'error')
                return redirect(url_for('login', logged_in=current_user.is_authenticated))
        else:
            flash('Wrong email', 'error')
            return redirect(url_for('login', logged_in=current_user.is_authenticated))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    name = request.args.get("name")
    return render_template("secrets.html", name=name, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/download', methods=["GET"])
@login_required
def download():
    filename = "files/cheat_sheet.pdf"
    return send_from_directory('static',
                               filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
