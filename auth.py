from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash
from models import db, User, UserRole
from datetime import datetime, timedelta
import logging

auth_bp = Blueprint('auth', __name__)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(), 
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), 
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')

class FirstLoginPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[
        DataRequired(), 
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), 
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Set Password')

# Routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and not user.is_locked() and user.check_password(form.password.data):
            # Reset failed login count on successful login
            user.failed_login_count = 0
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=form.remember_me.data)
            
            # Check if user must change password
            if user.must_change_password:
                flash('You must change your password before continuing.', 'warning')
                return redirect(url_for('auth.first_login_password'))
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('index')
            return redirect(next_page)
        else:
            # Handle failed login
            if user:
                user.failed_login_count = (user.failed_login_count or 0) + 1
                # Lock account after 5 failed attempts for 15 minutes
                if user.failed_login_count >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash('Account locked due to too many failed login attempts. Try again in 15 minutes.', 'error')
                db.session.commit()
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html', title='Sign In', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            current_user.must_change_password = False
            db.session.commit()
            flash('Your password has been updated.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Current password is incorrect.', 'error')
    
    return render_template('auth/change_password.html', title='Change Password', form=form)

@auth_bp.route('/first-login-password', methods=['GET', 'POST'])
def first_login_password():
    # Allow access without login for first-time password setup
    if current_user.is_authenticated and not current_user.must_change_password:
        return redirect(url_for('index'))
    
    # If not authenticated, find the default admin user that needs password change
    if not current_user.is_authenticated:
        admin_user = User.query.filter_by(username='admin', must_change_password=True).first()
        if not admin_user:
            flash('No user found requiring password setup.', 'error')
            return redirect(url_for('auth.login'))
        # Auto-login the admin user for password setup
        login_user(admin_user)
    
    form = FirstLoginPasswordForm()
    if form.validate_on_submit():
        current_user.set_password(form.new_password.data)
        current_user.must_change_password = False
        db.session.commit()
        flash('Password set successfully. Welcome to NetScan!', 'success')
        return redirect(url_for('index'))
    
    return render_template('auth/first_login_password.html', title='Set Password', form=form)