from flask import Blueprint, render_template, request, flash
import flask
from flask_login import login_required, current_user
import flask_login
from website.models import Users, db
from bs4 import BeautifulSoup as soup
from urllib.request import urlopen as ureq

views = Blueprint('views', __name__)


# When home url is on:
# login_required makes sure we must be logged-in to access home page

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    # HERE IS THE CODE FOR ADDING NEW CUSTOMER
    return render_template("home.html", user=current_user)


