from flask import render_template, request, redirect, url_for, flash, session, jsonify
from flask import Blueprint
admin_bp = Blueprint('admin', __name__)
from pymongo import MongoClient
import re

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['UserDB']
users_collection = db['users']
devices_collection = db['devices']

# Regex for validation
MAC_REGEX = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
IPV4_REGEX = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
IPV6_REGEX = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'

@admin_bp.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    users = list(users_collection.find({}, {'_id': 0, 'username': 1, 'password': 1, 'is_admin': 1}))
    devices = list(devices_collection.find({}, {'_id': 0, 'mac': 1, 'ip': 1}))
    return render_template('admin.html', users=users, devices=devices)

@admin_bp.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    username = request.form['username']
    password = request.form['password']

    existing_user = users_collection.find_one({'username': username})
    if existing_user:
        flash(f'User "{username}" already exists!', 'error')
    else:
        users_collection.insert_one({'username': username, 'password': password, 'is_admin': False})
        flash(f'User "{username}" added successfully!', 'success')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/add_device', methods=['POST'])
def add_device():
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    mac = request.form['mac']
    ip = request.form['ip']

    if not re.match(MAC_REGEX, mac):
        flash('Invalid MAC address format! Please try again', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    if not (re.match(IPV4_REGEX, ip) or re.match(IPV6_REGEX, ip)):
        flash('Invalid IP address format! Please try again', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    existing_device_mac = devices_collection.find_one({'mac': mac})
    existing_device_ip = devices_collection.find_one({'ip': ip})
    if existing_device_mac or existing_device_ip:
        flash(f'Device with MAC "{mac}" or IP "{ip}" already exists!', 'error')
    else:
        devices_collection.insert_one({'mac': mac, 'ip': ip})
        flash(f'Device with MAC "{mac}" and IP "{ip}" added successfully!', 'success')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/edit_user', methods=['POST'])
def edit_user():
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    original_username = request.form['original_username']
    username = request.form['username']
    password = request.form['password']

    user = users_collection.find_one({'username': original_username})
    if user:
        users_collection.update_one(
            {'username': original_username},
            {'$set': {'username': username, 'password': password}}
        )
        flash(f'User "{original_username}" updated successfully!', 'success')
    else:
        flash('User not found!', 'error')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/edit_device', methods=['POST'])
def edit_device():
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    original_mac = request.form['original_mac']
    mac = request.form['mac']
    ip = request.form['ip']

    if not re.match(MAC_REGEX, mac):
        flash('Invalid MAC address format! Please try again', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    if not (re.match(IPV4_REGEX, ip) or re.match(IPV6_REGEX, ip)):
        flash('Invalid IP address format! Please try again', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    device = devices_collection.find_one({'mac': original_mac})
    if device:
        devices_collection.update_one(
            {'mac': original_mac},
            {'$set': {'mac': mac, 'ip': ip}}
        )
        flash(f'Device with MAC "{original_mac}" updated successfully!', 'success')
    else:
        flash('Device not found!', 'error')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    user = users_collection.find_one({'username': username})
    if user:
        users_collection.delete_one({'username': username})
        flash(f'User {username} deleted successfully!', 'success')
    else:
        flash('User not found!', 'error')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/delete_device/<mac>', methods=['POST'])
def delete_device(mac):
    if not session.get('is_admin'):
        return redirect(url_for('auth.home'))

    device = devices_collection.find_one({'mac': mac})
    if device:
        devices_collection.delete_one({'mac': mac})
        flash(f'Device with MAC {mac} deleted successfully!', 'success')
    else:
        flash('Device not found!', 'error')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/view_devices')
def view_devices():
    if not session.get('user_id'):
        return redirect(url_for('auth.home'))

    devices = list(devices_collection.find())
    return render_template('view.html', devices=devices)

@admin_bp.route('/select_device/<ip>')
def select_device(ip):
    device = devices_collection.find_one({'ip': ip})
    if device and device.get('locked_by'):
        flash('This device is locked by another user. Please try again later.', 'error')
        return redirect(url_for('admin.view_devices'))
    
    devices_collection.update_one({'ip': ip}, {'$set': {'locked_by': session['user_id']}})
    return redirect(url_for('iperf.index', ip=ip))

@admin_bp.route('/release_device/<ip>', methods=['POST'])
def release_device(ip):
    device = devices_collection.find_one({'ip': ip})
    if device and device.get('locked_by') == session['user_id']:
        devices_collection.update_one({'ip': ip}, {'$set': {'locked_by': None}})
        flash('Device released successfully.', 'success')
    else:
        flash('You do not have permission to release this device.', 'error')
    return redirect(url_for('admin.view_devices'))

@admin_bp.route('/unlock_device', methods=['POST'])
def unlock_device():
    data = request.json
    device_id = data.get('device_id')

    if not device_id:
        return jsonify({"success": False, "message": "Device ID is required."}), 400

    result = devices_collection.update_one(
        {"_id": device_id},
        {"$set": {"locked_by": None}}
    )

    if result.modified_count > 0:
        return jsonify({"success": True, "message": "Device unlocked successfully."})
    else:
        return jsonify({"success": False, "message": "Device not found or already unlocked."}), 404

@admin_bp.route('/get_users')
def get_users():
    users = list(users_collection.find({}, {'_id': 0, 'username': 1, 'is_admin': 1}))
    return jsonify(users)

@admin_bp.route('/get_devices')
def get_devices():
    devices = list(devices_collection.find({}, {'_id': 0, 'mac': 1, 'ip': 1, 'locked_by': 1}))
    return jsonify(devices)