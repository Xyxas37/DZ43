from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)  # 🔹 Создаем объект базы данных
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# 🔹 Функция загрузки пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from app.models import User  # 🔹 Импортируем здесь, чтобы избежать циклической зависимости
    return User.query.get(int(user_id))

from app import routes  # Импортируем маршруты после инициализации db
