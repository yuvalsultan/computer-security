from . import db
from flask_login import UserMixin
import requests
from bs4 import BeautifulSoup as soup
from urllib.request import urlopen as ureq


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    password_history = db.Column(db.Text)
    first_name = db.Column(db.String(150))

    def get_password_history(self):
        return self.password_history

    def __init__(self, email, first_name, password,password_history):
        self.email = email
        self.first_name = first_name
        self.password = password
        self.password_history = password_history
