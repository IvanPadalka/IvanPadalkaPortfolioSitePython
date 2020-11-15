

from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from .models import User
from . import db


auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password): 
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():

    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user_email = User.query.filter_by(email=email).first()

    if user_email:
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    user_name = User.query.filter_by(name=name).first()
    #boolean_var=Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,user_name)
    if user_name:
        flash('Name already exists')
        return redirect(url_for('auth.signup'))

    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@auth.route('/update', methods=['POST','GET'])
@login_required
def update():
        form = User(request.form)
        if form.validate_on_submit():
            form.username.email = current_user.email
            form.username.name = current_user.name

            user_email = User.query.filter_by(email=request.form.get('email')).first()

            if user_email.data != current_user.email:
                flash('Email address already exists')
                return redirect(url_for('main.profile'))

            user_name = User.query.filter_by(name=request.form.get('name')).first()

            if user_name.data != current_user.username:
                flash('Name already exists')
                return redirect(url_for('main.profile'))

            if(request.form.get('password') != request.form.get('confirm_password')):
                flash('Password does not to match')
                return redirect(url_for('main.profile'))


            current_user.email = request.form.get('email')
            current_user.name = request.form.get('name')
            current_user.password = request.form.get('password')
            current_user.about_me = request.form.get('about_me')
            current_user.last_seen = request.form.get('last_seen')
            # if form.image_file.data:
            current_user.image_file = request.form.get('image')

            return redirect(url_for('main.index'))
        elif request.method == 'GET':
            form.name.data == current_user.name
            form.email.data == current_user.email

