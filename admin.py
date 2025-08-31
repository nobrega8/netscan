from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Optional, ValidationError
from functools import wraps
from models import db, User, UserRole
from datetime import datetime

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Decorators
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.can_admin():
            flash('Admin privileges required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if isinstance(required_role, str):
                role = UserRole(required_role)
            else:
                role = required_role
            
            if not current_user.has_role(role) and not current_user.can_admin():
                flash('Insufficient privileges.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Forms
class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[Length(min=8, max=255)])
    role = SelectField('Role', choices=[
        (UserRole.VIEWER.value, 'Viewer'),
        (UserRole.EDITOR.value, 'Editor'),
        (UserRole.ADMIN.value, 'Admin')
    ], validators=[DataRequired()])
    must_change_password = BooleanField('Must Change Password on Next Login')
    submit = SubmitField('Save User')
    
    def __init__(self, user=None, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        self.user = user
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user and user != self.user:
            raise ValidationError('Username already exists.')

class EditUserForm(UserForm):
    def __init__(self, user, *args, **kwargs):
        super(EditUserForm, self).__init__(user, *args, **kwargs)
        # Password is optional for edit
        self.password.validators = [Optional(), Length(min=8, max=255)]

# Routes
@admin_bp.route('/users')
@admin_required
def users():
    users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', title='User Management', users=users)

@admin_bp.route('/users/new', methods=['GET', 'POST'])
@admin_required
def new_user():
    form = UserForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            role=UserRole(form.role.data),
            must_change_password=form.must_change_password.data
        )
        if form.password.data:
            user.set_password(form.password.data)
        else:
            # Set a random password that must be changed
            import secrets
            user.set_password(secrets.token_urlsafe(16))
            user.must_change_password = True
        
        db.session.add(user)
        try:
            db.session.commit()
            flash(f'User {user.username} created successfully.', 'success')
            return redirect(url_for('admin.users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
    
    return render_template('admin/user_form.html', title='New User', form=form)

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent editing the last admin user's role
    if user.role == UserRole.ADMIN:
        admin_count = User.query.filter_by(role=UserRole.ADMIN).count()
        if admin_count == 1:
            flash('Cannot modify the last admin user.', 'warning')
    
    form = EditUserForm(user)
    if form.validate_on_submit():
        user.username = form.username.data
        user.role = UserRole(form.role.data)
        user.must_change_password = form.must_change_password.data
        
        if form.password.data:
            user.set_password(form.password.data)
            user.must_change_password = True
        
        try:
            db.session.commit()
            flash(f'User {user.username} updated successfully.', 'success')
            return redirect(url_for('admin.users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'error')
    elif request.method == 'GET':
        form.username.data = user.username
        form.role.data = user.role.value
        form.must_change_password.data = user.must_change_password
    
    return render_template('admin/user_form.html', title='Edit User', form=form, user=user)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting self
    if user == current_user:
        return jsonify({'success': False, 'message': 'Cannot delete your own account.'}), 400
    
    # Prevent deleting the last admin
    if user.role == UserRole.ADMIN:
        admin_count = User.query.filter_by(role=UserRole.ADMIN).count()
        if admin_count == 1:
            return jsonify({'success': False, 'message': 'Cannot delete the last admin user.'}), 400
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': f'User {user.username} deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error deleting user: {str(e)}'}), 500

@admin_bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@admin_required
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.failed_login_count = 0
    user.locked_until = None
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'User {user.username} unlocked successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error unlocking user: {str(e)}'}), 500

@admin_bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    
    # Generate a temporary password
    import secrets
    temp_password = secrets.token_urlsafe(12)
    user.set_password(temp_password)
    user.must_change_password = True
    user.failed_login_count = 0
    user.locked_until = None
    
    try:
        db.session.commit()
        return jsonify({
            'success': True, 
            'message': f'Password reset for {user.username}.',
            'temp_password': temp_password
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error resetting password: {str(e)}'}), 500