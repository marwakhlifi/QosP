from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from pymongo import MongoClient
from flask import Blueprint
import threading
from datetime import datetime, timedelta
import re
import paramiko
import subprocess
import os
import json
import threading
import queue
from werkzeug.security import generate_password_hash, check_password_hash
auth_bp = Blueprint('auth', __name__, template_folder='../../../templates')


# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['UserDB']  # Utilisez le nom de la base de données correcte
users_collection = db['users']  # Utilisez le nom de la collection des utilisateurs
devices_collection = db['devices']  # Collection pour les dispositifs

# Regex pour la validation
MAC_REGEX = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
IPV4_REGEX = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
IPV6_REGEX = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'

# Global queue to store iPerf results
iperf_result_queue = queue.Queue()

@auth_bp.route('/')
def home():
    return render_template('hello.html')
@auth_bp.route('/auth.network')
def network_page():
    return render_template('network.html')

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
        # No login_time needed for admin
        flash('Admin login successful!', 'success')
        return redirect(url_for('auth.admin_dashboard'))

    user = users_collection.find_one({'username': username})
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['username']
        session['is_admin'] = False
        session['login_time'] = datetime.now().timestamp()  # Only for regular users
        flash(f'Welcome back, {username}!', 'success')
        return redirect(url_for('auth.network_page'))
    else:
        flash('Invalid credentials, please try again.', 'error')
        return redirect(url_for('auth.home'))
    
    
@auth_bp.before_app_request
def check_session_expiry():
    # Skip for static files and login-related endpoints
    if request.endpoint in ['static', 'auth.login', 'auth.login_page']:
        return
    
    # Admin users bypass all session expiry checks
    if session.get('is_admin'):
        return
    
    # Regular user session check
    if 'user_id' in session and 'login_time' in session:
        current_time = datetime.now().timestamp()
        login_time = session['login_time']
        
        # Check if session has expired (30 minutes)
        if current_time - login_time > 1800:
            user_id = session['user_id']
            
            # Release all devices locked by this user
            devices_collection.update_many(
                {'locked_by': user_id},
                {'$unset': {'locked_by': ""}}
            )
            
            # Clear any active timers for this user's devices
            devices = devices_collection.find({'locked_by': user_id})
            for device in devices:
                ip = device['ip']
                if ip in unlock_timers:
                    unlock_timers[ip].cancel()
                    del unlock_timers[ip]
            
            # Clear the session
            session.clear()
            flash('Your session has expired after 30 minutes of inactivity.', 'warning')
            return redirect(url_for('auth.home'))
    
    # For routes that require authentication but user isn't logged in
    elif not request.endpoint in ['auth.home']:
        return redirect(url_for('auth.home'))

    
@auth_bp.route('/admin_dashboard/') 
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    users = list(users_collection.find({}, {'_id': 0, 'username': 1, 'password': 1, 'is_admin': 1}))
    devices = list(devices_collection.find({}, {'_id': 0, 'mac': 1, 'ip': 1}))
    return render_template('admin.html', users=users, devices=devices)

@auth_bp.route('/select_device/<ip>')
def select_device(ip):
    device = devices_collection.find_one({'ip': ip})
    if device and device.get('locked_by'):
        flash('This device is locked by another user. Please try again later.', 'error')
        return redirect(url_for('auth.view_devices'))
    
    # Verrouiller l'appareil pour l'utilisateur actuel
    devices_collection.update_one(
        {'ip': ip},
        {'$set': {'locked_by': session['user_id']}}
    )
    
    # Lancer le timer pour déverrouiller automatiquement après 30 minutes
    auto_unlock_device(ip, session['user_id'])
    
    return redirect(url_for('auth.index', ip=ip))

@auth_bp.route('/release_device/<ip>', methods=['POST'])
def release_device(ip):
    device = devices_collection.find_one({'ip': ip})
    if device and device.get('locked_by') == session['user_id']:
        devices_collection.update_one(
            {'ip': ip},
            {'$unset': {'locked_by': ""}}
        )
        # Annuler le timer si il existe
        if ip in unlock_timers:
            unlock_timers[ip].cancel()
            del unlock_timers[ip]
        flash('Device released successfully.', 'success')
    else:
        flash('You do not have permission to release this device.', 'error')
    return redirect(url_for('auth.view_devices'))

@auth_bp.route('/logout_and_release_devices')
def logout_and_release_devices():
    user_id = session.get('user_id')
    
    if user_id:
        # Release all devices locked by this user
        devices = devices_collection.find({'locked_by': user_id})
        for device in devices:
            ip = device['ip']
            # Cancel any active timers
            if ip in unlock_timers:
                unlock_timers[ip].cancel()
                del unlock_timers[ip]
        
        devices_collection.update_many(
            {'locked_by': user_id},
            {'$unset': {'locked_by': ""}}
        )
    
    session.clear()
    return redirect(url_for('auth.home'))


@auth_bp.route('/count')
def index():
    selected_ip = request.args.get('ip')
    print(f"Selected IP: {selected_ip}")  
    return render_template('clientscount.html', selected_ip=selected_ip)


@auth_bp.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect(url_for('auth.home'))

@auth_bp.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('is_admin'):
        flash('Unauthorized access!', 'error')
        return redirect(url_for('auth.home'))

    username = request.form['username']
    password = request.form['password']

    existing_user = users_collection.find_one({'username': username})
    if existing_user:
        flash(f'User "{username}" already exists!', 'error')
    else:
        # Hash the password before storing
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,  # Store hashed version
            'is_admin': False
        })
        flash(f'User "{username}" added successfully!', 'success')
    return redirect(url_for('auth.admin_dashboard'))


@auth_bp.route('/add_device', methods=['POST'])
def add_device():
    if not session.get('is_admin'):
        return redirect(url_for('home'))

    mac = request.form['mac']
    ip = request.form['ip']

    if not re.match(MAC_REGEX, mac):
        flash('Invalid MAC address format! Please try again', 'error')
        return redirect(url_for('auth.admin_dashboard'))

    if not (re.match(IPV4_REGEX, ip) or re.match(IPV6_REGEX, ip)):
        flash('Invalid IP address format! Please try again', 'error')
        return redirect(url_for('auth.admin_dashboard'))

    existing_device_mac = devices_collection.find_one({'mac': mac})
    existing_device_ip = devices_collection.find_one({'ip': ip})
    if existing_device_mac or existing_device_ip:
        flash(f'Device with MAC "{mac}" or IP "{ip}" already exists!', 'error')
    else:
        devices_collection.insert_one({'mac': mac, 'ip': ip})
        flash(f'Device with MAC "{mac}" and IP "{ip}" added successfully!', 'success')

    return redirect(url_for('auth.admin_dashboard'))
@auth_bp.route('/edit_user', methods=['POST'])
def edit_user():
    if not session.get('is_admin'):
        return redirect(url_for('home'))

    original_username = request.form['original_username']
    username = request.form['username']
    password = request.form['password']

    user = users_collection.find_one({'username': original_username})
    if user:
        # Hash the new password before storing
        hashed_password = generate_password_hash(password)
        users_collection.update_one(
            {'username': original_username},
            {'$set': {
                'username': username,
                'password': hashed_password  # Store hashed version
            }}
        )
        flash(f'User "{original_username}" updated successfully!', 'success')
    else:
        flash('User not found!', 'error')

    return redirect(url_for('auth.admin_dashboard'))


@auth_bp.route('/edit_device', methods=['POST'])
def edit_device():
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    original_mac = request.form['original_mac']
    mac = request.form['mac']
    ip = request.form['ip']

    if not re.match(MAC_REGEX, mac):
        flash('Invalid MAC address format! Please try again', 'error')
        return redirect(url_for('auth.admin_dashboard'))

    if not (re.match(IPV4_REGEX, ip) or re.match(IPV6_REGEX, ip)):
        flash('Invalid IP address format! Please try again', 'error')
        return redirect(url_for('auth.admin_dashboard'))

    device = devices_collection.find_one({'mac': original_mac})
    if device:
        devices_collection.update_one(
            {'mac': original_mac},
            {'$set': {'mac': mac, 'ip': ip}}
        )
        flash(f'Device with MAC "{original_mac}" updated successfully!', 'success')
    else:
        flash('Device not found!', 'error')

    return redirect(url_for('auth.admin_dashboard'))

@auth_bp.route('/view_devices')
def view_devices():
    if not session.get('user_id'):
        return redirect(url_for('home'))

    devices = list(devices_collection.find())
    return render_template('view.html', devices=devices)

@auth_bp.route('/get_users')
def get_users():
    users = list(users_collection.find({}, {'_id': 0, 'username': 1, 'is_admin': 1}))
    return jsonify(users)

@auth_bp.route('/get_devices')
def get_devices():
    devices = list(devices_collection.find({}, {'_id': 0, 'mac': 1, 'ip': 1, 'locked_by': 1}))
    return jsonify(devices)


@auth_bp.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    user = users_collection.find_one({'username': username})
    if user:
        users_collection.delete_one({'username': username})
        flash(f'User {username} deleted successfully!', 'success')
    else:
        flash('User not found!', 'error')

    return redirect(url_for('auth.admin_dashboard'))

@auth_bp.route('/delete_device/<mac>', methods=['POST'])
def delete_device(mac):
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    device = devices_collection.find_one({'mac': mac})
    if device:
        devices_collection.delete_one({'mac': mac})
        flash(f'Device with MAC {mac} deleted successfully!', 'success')
    else:
        flash('Device not found!', 'error')

    return redirect(url_for('auth.admin_dashboard'))

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.home'))

unlock_timers = {}

def auto_unlock_device(ip, user_id):
    def unlock():
        device = devices_collection.find_one({'ip': ip})
        if device and device.get('locked_by') == user_id:
            # Unlock the device
            devices_collection.update_one(
                {'ip': ip},
                {'$unset': {'locked_by': ""}}
            )
            print(f"Device {ip} automatically unlocked after 30 minutes.")
            
            # Note: We can't directly modify the session here as it's in a background thread
            # The actual logout will be handled by the before_request handler
            
        # Remove the timer from the dictionary after execution
        if ip in unlock_timers:
            del unlock_timers[ip]
    
    # Cancel the old timer if it exists
    if ip in unlock_timers:
        unlock_timers[ip].cancel()
    
    # Create a new timer and store it
    timer = threading.Timer(1800, unlock)  # 1800 seconds = 30 minutes
    timer.start()
    unlock_timers[ip] = timer

    