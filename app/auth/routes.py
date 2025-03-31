from flask import render_template, request, redirect, url_for, flash, session
from . import bp as auth_bp  # Fix import here

from pymongo import MongoClient


# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['UserDB']
users_collection = db['users']

@auth_bp.route('/')
def home():
    return render_template('hello.html')

@auth_bp.route('/login')
def login_page():
    return render_template('login.html')

@auth_bp.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if username == "admin" and password == "admin123":
        session['user_id'] = "admin"
        session['is_admin'] = True
        return redirect(url_for('admin.admin_dashboard'))

    user = users_collection.find_one({'username': username, 'password': password})
    if user:
        session['user_id'] = user['username']
        session['is_admin'] = False
        return redirect(url_for('admin.view_devices'))
    else:
        flash('Invalid credentials, please try again.')
        return redirect(url_for('auth.home'))

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.home'))

@auth_bp.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect(url_for('auth.home'))
