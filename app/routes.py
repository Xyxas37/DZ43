from flask import render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user, login_user, logout_user
from app import app, db, bcrypt
from app.forms import EditProfileForm, LoginForm, RegistrationForm
from app.models import User






# 📌 Главная страница
@app.route('/')
def home():
    return render_template('home.html')

# 📌 Редактирование профиля (Только для авторизованных пользователей)
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:  # Если пользователь ввел новый пароль
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            current_user.password = hashed_password

        db.session.commit()
        flash('Профиль успешно обновлен!', 'success')
        return redirect(url_for('edit_profile'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('edit_profile.html', form=form)

# 📌 Регистрация пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрировались! Теперь войдите в аккаунт.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# 📌 Авторизация пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Ошибка входа! Проверьте логин и пароль.', 'danger')

    return render_template('login.html', form=form)

# 📌 Выход из аккаунта
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

# 📌 Личный кабинет (Только для авторизованных пользователей)
@app.route('/account')
@login_required
def account():
    return render_template('account.html')

