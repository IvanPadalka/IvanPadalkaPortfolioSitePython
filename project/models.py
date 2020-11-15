# models.py

from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    image_file = db.Column(db.String(20), nullable=False, default='guest.png')
    about_me = db.Column(db.String(800))
    last_seen = db.Column(db.String(1000))