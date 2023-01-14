from flask import Blueprint, render_template, request, flash
import flask
from flask_login import login_required, current_user
import flask_login
from website.models import Users, db, Costumers
from bs4 import BeautifulSoup as soup
from urllib.request import urlopen as ureq
import json
views = Blueprint('views', __name__)


# When home url is on:
# login_required makes sure we must be logged-in to access home page

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    costumers=''
    if request.method == 'POST':
        fullName = request.form['fullName']
        email = request.form['email']

        new_costumer = Costumers(fullName=fullName, email=email)
        db.session.add(new_costumer)
        db.session.commit()

    return render_template("home.html", user=current_user, text=costumers)

@views.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    costumers=''

    if request.method == 'POST':
        print(request.form)
        fullName = request.form['fullName']
        query = "select * from Costumers where fullName = '"+ fullName + "'" # reveal the entire table with input: ' or 1=1 --
        print(query)
        costumersQuery = db.engine.execute(query)
        costumers =  [row[2] for row in costumersQuery]
        # costumersQuery = Costumers.query.filter_by(email=email).first()
        if costumers:
            # costumers = costumersQuery.fullName
            
            print(costumers)
        else:
            costumers=""
            flash("Costumer does'n exits", category='error')
    return render_template("search.html", user=current_user, text=costumers)