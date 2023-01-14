from flask import Blueprint, render_template, request, flash
import flask
from flask_login import login_required, current_user
import flask_login
from website.models import Users, db, Costumers
from bs4 import BeautifulSoup as soup
from urllib.request import urlopen as ureq

views = Blueprint('views', __name__)


# When home url is on:
# login_required makes sure we must be logged-in to access home page

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    text = ''
    if request.method == 'POST':
        fullName = request.form['fullName']
        email = request.form['email']

        new_costumer = Costumers(fullName=fullName, email=email)
        db.session.add(new_costumer)
        db.session.commit()
        costumer = Costumers.query.filter_by(email=email).first()
        text = costumer.fullName
        print(text)

    return render_template("home.html", user=current_user, text=text)


