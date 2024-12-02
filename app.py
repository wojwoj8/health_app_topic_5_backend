from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
bcrypt = Bcrypt(app)
DATABASE = 'users.db'

# Utility function to connect to the database
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    print(data)
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        with get_db_connection() as conn:
            conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            conn.commit()
        return jsonify({'message': 'User registered successfully.'}), 201
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
        return jsonify({'message': 'Login successful.'}), 200
    else:
        return jsonify({'error': 'Invalid email or password.'}), 401

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))