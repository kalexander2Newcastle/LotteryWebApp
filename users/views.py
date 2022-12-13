# IMPORTS
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from markupsafe import Markup

from app import db
from models import User
from users.forms import RegisterForm, LoginForm
import bcrypt

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # Generates salt
        Psalt = bcrypt.gensalt()

        # Creates a new variable 'Bpassword' and converts it into bytes
        Bpassword = user.password.encode('utf-8')

        # Hashing the new byte-converted password
        Bpassword_hash = bcrypt.hashpw(Bpassword, Psalt)

        if not user \
                or not bcrypt.checkpw(form.password.data.encode('utf-8'), Bpassword_hash) \
                or not pyotp.TOTP(user.pinkey).verify(form.pin.data):
            session['authentication_attempts'] += 1
            if session.get('authentication_attempts') >= 3:
                flash(Markup('Number of incorrect login attempts exceeded. '
                             'Please click <a href="/reset">here</a> to reset.'))
                return render_template('users/login.html')
            flash('Please check your login details and try again, {} login attempts remaining'
                  .format(3 - session.get('authentication_attempts')))
            return render_template('users/login.html', form=form)
        login_user(user)
        return render_template('users/profile.html')
    else:
        return render_template('users/login.html', form=form)


@users_blueprint.route('/logout')
def logout():
    logout_user()
    return render_template('main/index.html')


# view user profile
@users_blueprint.route('/profile')
@login_required
def profile():
    return render_template('users/profile.html', name=current_user.firstname)


@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)
