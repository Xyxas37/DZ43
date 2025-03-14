from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from app import db  # ✅ db импортируется из app/__init__.py

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
