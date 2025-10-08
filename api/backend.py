from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import requests
from datetime import datetime, timedelta
import pymongo
import bcrypt
import jwt
import os
import re
import uuid

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"]}})

# Configuration
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb+srv://Auxe:Auxe@cluster0.prytrzw.mongodb.net/")
JWT_SECRET = os.getenv("JWT_SECRET", "aerial-super-secret-jwt-key-2025-change-this-for-production")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1425329586421497866/iWIXz1J9taUbu6WPBOyTb8VpygU7SrWGkfqJWiZzCcKa6ZGWxXr4HeXki3TbVuMRvI2i")
DB_NAME = "aerial_auth"

# Initialize MongoDB
mongo_client = None
db = None
users_collection = None
keys_collection = None

try:
    if MONGODB_URI:
        mongo_client = pymongo.MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        db = mongo_client[DB_NAME]
        users_collection = db.users
        keys_collection = db.keys
        # Test connection
        users_collection.find_one({})
        users_collection.create_index("email", unique=True)
        keys_collection.create_index("key", unique=True)
        print("Connected to MongoDB successfully")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    users_collection = None
    keys_collection = None

def log_and_print(message, level="INFO"):
    print(f"[{level}] {message}")
    if DISCORD_WEBHOOK_URL:
        try:
            colors = {"INFO": 0x00ff00, "ERROR": 0xff0000, "WARNING": 0xffff00, "AUTH": 0x0099ff}
            embed = {
                "title": f"Aerial Auth - {level}",
                "description": message,
                "color": colors.get(level, 0x808080),
                "timestamp": datetime.utcnow().isoformat()
            }
            requests.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]}, timeout=3)
        except Exception as e:
            print(f"Failed to send Discord webhook: {e}")

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def generate_jwt_token(user_data, remember=False):
    if not JWT_SECRET:
        raise ValueError("JWT_SECRET not configured")
    expiry = datetime.utcnow() + (timedelta(days=30) if remember else timedelta(hours=24))
    payload = {
        'user_id': str(user_data['_id']),
        'email': user_data['email'],
        'username': user_data['username'],
        'exp': expiry,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    if not JWT_SECRET:
        raise ValueError("JWT_SECRET not configured")
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return None

@app.route('/')
def home():
    log_and_print("Serving login page")
    try:
        with open('index.html', 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Login - Aerial</title></head>
        <body style="background:#0f0f0f;color:white;font-family:Arial;padding:20px;">
            <h1>Aerial Login</h1>
            <p>index.html file not found</p>
            <p>Please create index.html in the project root</p>
        </body>
        </html>
        """

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response, 200
    
    log_and_print("Login attempt received")
    
    try:
        if users_collection is None:
            return jsonify({'success': False, 'message': 'Database connection error'}), 500
        
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON data'}), 400
        
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        remember = data.get('remember', False)
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password required'}), 400
        
        user = users_collection.find_one({'email': email})
        if user is None:
            log_and_print(f"Login attempt with non-existent email: {email}", "AUTH")
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        if not verify_password(password, user['password']):
            log_and_print(f"Failed password for: {email}", "AUTH")
            return jupytext({'success': False, 'message': 'Invalid email or password'}), 401
        
        token = generate_jwt_token(user, remember)
        
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'lastLogin': datetime.utcnow(), 'lastLoginIP': request.remote_addr or 'unknown'}}
        )
        
        log_and_print(f"Successful login: {user['username']} ({email})", "AUTH")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'createdAt': user['createdAt'].isoformat() if user.get('createdAt') else None
            }
        })
        
    except Exception as e:
        log_and_print(f"Login error: {str(e)}", "ERROR")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/verify-token', methods=['GET', 'OPTIONS'])
def verify_token():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET')
        return response, 200
        
    try:
        if not JWT_SECRET:
            return jsonify({'success': False, 'message': 'JWT not configured'}), 500
            
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'success': False, 'message': 'No token'}), 401
        
        token = auth_header.replace('Bearer ', '')
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        
        return jsonify({
            'success': True,
            'user': {
                'id': payload['user_id'],
                'email': payload['email'],
                'username': payload['username']
            }
        })
    except:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401

@app.route('/api/authenticate', methods=['POST', 'OPTIONS'])
def authenticate():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response, 200
    
    log_and_print("Authentication attempt received")
    
    try:
        if keys_collection is None:
            return jsonify({'success': False, 'message': 'Database connection error'}), 500
        
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON data'}), 400
        
        key = data.get('key')
        hwid = data.get('hwid')
        
        if not key or not hwid:
            return jsonify({'success': False, 'message': 'Key and HWID required'}), 400
        
        key_doc = keys_collection.find_one({'key': key})
        if not key_doc:
            log_and_print(f"Invalid key attempt: {key}", "AUTH")
            return jsonify({'success': False, 'message': 'Invalid key'}), 401
        
        if key_doc.get('expiry') and datetime.utcnow() > key_doc['expiry']:
            log_and_print(f"Expired key: {key}", "AUTH")
            return jsonify({'success': False, 'message': 'Key expired'}), 401
        
        if key_doc['hwid'] is None:
            keys_collection.update_one({'key': key}, {'$set': {'hwid': hwid, 'last_auth': datetime.utcnow()}})
            log_and_print(f"Bound HWID for key: {key} to {hwid}", "AUTH")
            return jsonify({'success': True, 'message': 'Authentication successful (HWID bound)'})
        
        if hwid != key_doc['hwid']:
            log_and_print(f"HWID mismatch for key: {key} (expected {key_doc['hwid']}, got {hwid})", "AUTH")
            return jsonify({'success': False, 'message': 'HWID mismatch'}), 401
        
        keys_collection.update_one({'key': key}, {'$set': {'last_auth': datetime.utcnow()}})
        log_and_print(f"Successful auth for key: {key}", "AUTH")
        return jsonify({'success': True, 'message': 'Authentication successful'})
    
    except Exception as e:
        log_and_print(f"Auth error: {str(e)}", "ERROR")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/keys/generate', methods=['POST', 'OPTIONS'])
def generate_key_api():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response, 200
    
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'success': False, 'message': 'No token'}), 401
    token = auth_header.replace('Bearer ', '')
    payload = verify_jwt_token(token)
    if not payload:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401
    
    try:
        data = request.get_json(silent=True)
        expiry_days = data.get('expiry_days')
        key = str(uuid.uuid4())
        expiry = None if expiry_days is None else datetime.utcnow() + timedelta(days=expiry_days)
        keys_collection.insert_one({
            'key': key,
            'hwid': None,
            'expiry': expiry,
            'created_at': datetime.utcnow(),
            'created_by': payload['user_id']
        })
        log_and_print(f"Generated key: {key} by user {payload['username']}", "INFO")
        return jsonify({'success': True, 'key': key, 'expiry': expiry.isoformat() if expiry else 'None'})
    except Exception as e:
        log_and_print(f"Key generate error: {str(e)}", "ERROR")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/keys/delete', methods=['POST', 'OPTIONS'])
def delete_key_api():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response, 200
    
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'success': False, 'message': 'No token'}), 401
    token = auth_header.replace('Bearer ', '')
    payload = verify_jwt_token(token)
    if not payload:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401
    
    try:
        data = request.get_json(silent=True)
        key = data.get('key')
        if not key:
            return jsonify({'success': False, 'message': 'Key required'}), 400
        result = keys_collection.delete_one({'key': key})
        if result.deleted_count == 0:
            return jsonify({'success': False, 'message': 'Key not found'}), 404
        log_and_print(f"Deleted key: {key} by user {payload['username']}", "INFO")
        return jsonify({'success': True, 'message': 'Key deleted'})
    except Exception as e:
        log_and_print(f"Key delete error: {str(e)}", "ERROR")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/keys/reset_hwid', methods=['POST', 'OPTIONS'])
def reset_hwid_api():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response, 200
    
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'success': False, 'message': 'No token'}), 401
    token = auth_header.replace('Bearer ', '')
    payload = verify_jwt_token(token)
    if not payload:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401
    
    try:
        data = request.get_json(silent=True)
        key = data.get('key')
        if not key:
            return jsonify({'success': False, 'message': 'Key required'}), 400
        result = keys_collection.update_one({'key': key}, {'$set': {'hwid': None}})
        if result.matched_count == 0:
            return jsonify({'success': False, 'message': 'Key not found'}), 404
        log_and_print(f"Reset HWID for key: {key} by user {payload['username']}", "INFO")
        return jsonify({'success': True, 'message': 'HWID reset'})
    except Exception as e:
        log_and_print(f"HWID reset error: {str(e)}", "ERROR")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/dashboard-stats', methods=['GET', 'OPTIONS'])
def dashboard_stats():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET')
        return response, 200
    
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'success': False, 'message': 'No token'}), 401
    token = auth_header.replace('Bearer ', '')
    payload = verify_jwt_token(token)
    if not payload:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401
    
    try:
        if keys_collection is None:
            log_and_print("Database connection is not available for dashboard stats", "ERROR")
            return jsonify({'success': False, 'message': 'Database connection error'}), 500
        
        total_keys = keys_collection.count_documents({})
        active_keys = keys_collection.count_documents({'expiry': {'$exists': True, '$gt': datetime.utcnow()}})
        expired_keys = keys_collection.count_documents({'expiry': {'$exists': True, '$lte': datetime.utcnow()}})
        
        recent_keys = list(keys_collection.find(
            {},
            {'key': 1, 'created_at': 1, '_id': 0}
        ).sort('created_at', -1).limit(20))
        
        return jsonify({
            'success': True,
            'data': {
                'totalKeys': total_keys,
                'activeKeys': active_keys,
                'expiredKeys': expired_keys,
                'recentActivities': [
                    {
                        'message': f"Generated key {key['key']}",
                        'type': 'success',
                        'time': key['created_at'].isoformat()
                    } for key in recent_keys
                ]
            }
        })
    except Exception as e:
        log_and_print(f"Dashboard stats error: {str(e)}", "ERROR")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'AERIAL AUTH IS ONLINE',
        'database': 'Connected' if users_collection is not None and keys_collection is not None else 'Disconnected',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/dashboard')
def dashboard():
    log_and_print("Serving dashboard page")
    try:
        with open('dashboard.html', 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        log_and_print("dashboard.html file not found", "ERROR")
        return jsonify({'success': False, 'message': 'Dashboard file not found'}), 404

# Add catch-all error handler
@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'message': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'success': False, 'message': 'Method not allowed'}), 405

# Vercel requires the app to be exported
if __name__ == '__main__':
    app.run(debug=True)
