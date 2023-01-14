import bcrypt
from flask import Blueprint, render_template, request, flash, redirect, url_for,session
import flask_login
from .models import Users
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import random
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import re
import json
with open ("password_config.json") as pass_config:
    CONFIG = json.load(pass_config)
auth = Blueprint('auth', __name__)


# When log-in url is on:

# Post method is on when submit button is pressed and then we take data with 'request' method and compare to data
# in DB. checks if email does exist and if passwords matches, and then logs in

def check_pass_comp(pass_complexity, password):
    pattern = re.compile(pass_complexity) #eg "[A-Za-z0-9]+"
    if pattern.match(password): 
        return True
    else: 
        return False


def check_history(num_of_pass_history,password,pass_history):
    print(pass_history[-num_of_pass_history:])
    for p in pass_history[-num_of_pass_history:]:
        if p:
            if bcrypt.checkpw(password.encode('utf-8'), p.encode('utf-8')):
                return False
    return True

def check_len(password,pass_len):
    return len(password) >= pass_len


def check_words(password, pass_forbidden):
    for w in pass_forbidden:
        if w in password:
            return False
    return True

def pass_requirements(password, password_history):
    pass_len = CONFIG['length']
    pass_complexity = CONFIG['complexity']
    num_of_pass_history = CONFIG['history']
    pass_forbidden = CONFIG['forbidden_words']
    
    valid_len = check_len(password, pass_len)
    is_complex = check_pass_comp(pass_complexity, password)
    not_in_history = check_history(num_of_pass_history,password,password_history.split(','))
    valid_words = check_words(password, pass_forbidden)
    if  valid_len and is_complex and not_in_history and valid_words:
        return False
    else:
        print("valid_len",valid_len)
        print("is_complex",is_complex)
        print("not_in_history",not_in_history)
        print("valid_words",valid_words)
        return True


@auth.route('/login', methods=['GET', 'POST'])
def login():
    print('login is active')

    try:
        session['attempts']-=1
        if session['attempts'] < 0:
            flash('Max retries exceeded! please try again later', category='error')
            return render_template("login.html", user=current_user)
    except:
        session['attempts'] = CONFIG['login_retries']

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        #Faulty behavior 
        query = f"select * from Users where email = '{email}' and password = '{password}'" # reveal the entire table with input: '' or 1=1
        print(query)
        faultyUser = db.engine.execute(query)
        users =  [row[0] for row in faultyUser]
        print (users)

        #solution
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

        user = Users.query.filter_by(email=email).first() #take this to the check if email is not in db

        if user: #take this to the check if email is not in db
            flash('Email already exists.', category='error')  #take this to the check if email is not in db
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif pass_requirements(password1,""):
             flash('Password doesn\'t match the requirements.', category='error')

        else:
            encoded_password = password1.encode('utf-8')
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(encoded_password, salt)
            new_user = Users(email=email, first_name=first_name, password=hashed, password_history=hashed.decode('ascii'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            print(password1)
            return redirect(url_for('views.home'))
    
    return render_template("sign_up.html", user=current_user)


@auth.route('/change', methods=['GET', 'POST'])
@login_required
def change():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password_1 = request.form.get('new_password_1')
        new_password_2 = request.form.get('new_password_2')

        encoded_user_password = current_password.encode('utf-8')
        if bcrypt.checkpw(encoded_user_password, current_user.password):
            if new_password_1 != new_password_2:
                flash('Passwords don\'t match.', category='error')
            elif pass_requirements(new_password_1,current_user.password_history):
                flash('Password doesn\'t match the requirements.', category='error')
            else:
                encoded_new_password = new_password_1.encode('utf-8')
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(encoded_new_password, salt)
                current_user.password = hashed
                current_user.password_history = current_user.password_history +"," +hashed.decode('ascii')
                db.session.commit()
                flash('Password changed successfully', category='success')
                return redirect(url_for('views.home'))
        else:
            flash('Incorrect password, please try again.', category='error')
    return render_template("change.html", user=current_user)



@auth.route('/forget_password_email' , methods=['GET', 'POST'])
def forget():
    if request.method == 'POST': 
        to_email_address = request.form.get('email_for_reset')

        user = Users.query.filter_by(email=to_email_address).first()
        if user:
            ###First version
            reset_key = hashlib.sha1(str(random.getrandbits(160)).encode('utf-8')).hexdigest()

            from_email_address = 'csproj23A@gmail.com'
            from_email_psw = 'oocwvzgpuaonhldu'

            message = reset_key

            email_context=ssl.create_default_context()

            smtp = smtplib.SMTP("smtp.gmail.com", 587)
            smtp.starttls(context=email_context)
            smtp.login(from_email_address, from_email_psw)
            smtp.sendmail(from_email_address, to_email_address, message)

            return redirect(url_for('auth.verify', messages = message , user_email = to_email_address))
        

            #Second version
            # from_email_address = 'csproj23A@gmail.com'
            # from_email_psw = 'oocwvzgpuaonhldu'
            
            # subject = 'Password reset key'
            # body = reset_key

            # message = MIMEMultipart()
            # message['From'] = from_email_address
            # message['To'] = to_email_address
            # message['Subject'] = subject
            # message.attach(MIMEText(body, 'plain'))

            # # email_context=ssl.create_default_context()

            # smtp = smtplib.SMTP("smtp.gmail.com", 587)
            # # smtp.starttls(context=email_context)
            # smtp.starttls()
            # smtp.login(from_email_address, from_email_psw)
            # smtp.sendmail(from_email_address, to_email_address, message)

            ############Do Something##############
            

        else:
            flash('Email does not exist.', category='error')        
    return render_template("forget_password_email.html", user=current_user)



@auth.route('/verify' , methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        sent_key = request.args['messages'] #get the message from the url_for
        check_key = request.form.get('key_for_reset')

        if sent_key == check_key:
            user_email = request.args['user_email'] 
            return redirect(url_for('auth.reset', user_email = user_email))
        else:
            flash('Key does not match , try again!', category='error')    
    return render_template('verify_email.html', user=current_user)


@auth.route('/reset' , methods=['GET', 'POST'])
def reset():
    current_user_email = request.args['user_email']
    user = Users.query.filter_by(email=current_user_email).first()

    if request.method == 'POST':
        new_password_1 = request.form.get('new_password_1')
        new_password_2 = request.form.get('new_password_2')

        
        if new_password_1 != new_password_2:
            flash('Passwords don\'t match.', category='error')
        elif pass_requirements(new_password_1,""):
            flash('Password doesn\'t match the requirements.', category='error')
        else:
            encoded_new_password = new_password_1.encode('utf-8')
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(encoded_new_password, salt)
            user.password = hashed
            user.password_history = user.password_history +"," +hashed.decode('ascii')
            db.session.commit()
            flash('Password changed successfully', category='success')
            return redirect(url_for('views.home'))
    
    return render_template('change_after_forget.html', user=current_user)

