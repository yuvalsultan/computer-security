import bcrypt
from flask import Blueprint, render_template, request, flash, redirect, url_for
import flask_login
from .models import Users
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


# When log-in url is on:

# Post method is on when submit button is pressed and then we take data with 'request' method and compare to data
# in DB. checks if email does exist and if passwords matches, and then logs in


@auth.route('/login', methods=['GET', 'POST'])
def login():
    print('login is active')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Users.query.filter_by(email=email).first()  # Searches email required
        if user:
            encoded_user_password = password.encode('utf-8')
            if bcrypt.checkpw(encoded_user_password, user.password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')

        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


# When Log out url is on, logs out , and redirected to login page
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


# When sing up url is on, and submit is pressed: takes input data, checks if user already exists in db,
# and more basic checks, if everything is ok, loads user to DB.
@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    print('sign up is active')

    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = Users.query.filter_by(email=email).first()

        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')

        else:
            encoded_password = password1.encode('utf-8')
            salt = bcrypt.gensalt()
            print(salt)
            hashed = bcrypt.hashpw(encoded_password, salt)
            print(hashed)
            new_user = Users(email=email, first_name=first_name, password=hashed)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)


@auth.route('/change', methods=['GET', 'POST'])
@login_required
def change():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password_1 = request.form.get('new_password_1')
        print(new_password_1)
        new_password_2 = request.form.get('new_password_2')

        encoded_user_password = current_password.encode('utf-8')
        if bcrypt.checkpw(encoded_user_password, current_user.password):
            if new_password_1 != new_password_2:
                flash('Passwords don\'t match.', category='error')
            else:
                encoded_new_password = new_password_1.encode('utf-8')
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(encoded_new_password, salt)
                current_user.password = hashed
                flash('Password changed successfully', category='success')
                return redirect(url_for('views.home'))
        else:
            flash('Incorrect password, please try again.', category='error')
    return render_template("change.html", user=current_user)


@auth.route('/forget')
def forget():
    return render_template("forget.html", user=current_user)
