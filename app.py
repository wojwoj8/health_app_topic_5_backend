from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import sqlite3
import base64
import json
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)
DATABASE = 'users.db'

# Utility function to connect to the database
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Simple encode/decode JWT for school project
def encode_jwt(payload):
    header = json.dumps({"alg": "none", "typ": "JWT"}).encode()
    payload = json.dumps(payload).encode()
    return f"{base64.urlsafe_b64encode(header).decode().strip('=')}.{base64.urlsafe_b64encode(payload).decode().strip('=')}"

def decode_jwt(token):
    try:
        header, payload = token.split(".")
        decoded_payload = base64.urlsafe_b64decode(payload + "==").decode()
        return json.loads(decoded_payload)
    except Exception:
        return None

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing.'}), 401
        try:
            data = decode_jwt(token)
            current_user_id = data['user_id']
        except Exception:
            return jsonify({'error': 'Invalid token.'}), 401
        return f(current_user_id, *args, **kwargs)
    return decorated

# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        with get_db_connection() as conn:
            cursor = conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            user_id = cursor.lastrowid
            conn.commit()
        return jsonify({'message': 'User registered successfully.', 'user_id': user_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered.'}), 409

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if user and bcrypt.check_password_hash(user['password'], password):
        token = encode_jwt({'user_id': user['id']})
        return jsonify({'token': token}), 200
    else:
        return jsonify({'error': 'Invalid email or password.'}), 401

# Blood oxygen level submission endpoint (protected)
@app.route('/blood-oxygen', methods=['POST'])
@token_required
def blood_oxygen(current_user_id):
    data = request.json
    blood_oxygen_level = data.get('blood_oxygen_level')
    date = data.get('date')

    if not blood_oxygen_level or not date:
        return jsonify({'error': 'Blood oxygen level and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            conn.execute(
                'INSERT INTO blood_oxygen_levels (user_id, blood_oxygen_level, date) VALUES (?, ?, ?)',
                (current_user_id, blood_oxygen_level, date)
            )
            conn.commit()
        return jsonify({'message': 'Blood oxygen level recorded successfully.'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
