from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import sqlite3
import base64
import json
from functools import wraps
from flask_cors import CORS, cross_origin

app = Flask(__name__)
bcrypt = Bcrypt(app)
DATABASE = 'users.db'
CORS(app, resources={r"/*": {"origins": "*"}})


# Utility function to connect to the database
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Simple encode/decode JWT
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


# Get all blood oxygen records for a user
@app.route('/blood-oxygen', methods=['GET'])
@token_required
def get_blood_oxygen_records(current_user_id):
    try:
        with get_db_connection() as conn:
            records = conn.execute(
                'SELECT * FROM blood_oxygen_levels WHERE user_id = ?',
                (current_user_id,)
            ).fetchall()
        return jsonify([dict(record) for record in records]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Update a blood oxygen record
@app.route('/blood-oxygen/<int:record_id>', methods=['PUT'])
@token_required
def update_blood_oxygen_record(current_user_id, record_id):
    data = request.json
    blood_oxygen_level = data.get('blood_oxygen_level')
    date = data.get('date')

    if not blood_oxygen_level or not date:
        return jsonify({'error': 'Blood oxygen level and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            result = conn.execute(
                'UPDATE blood_oxygen_levels SET blood_oxygen_level = ?, date = ? WHERE id = ? AND user_id = ?',
                (blood_oxygen_level, date, record_id, current_user_id)
            )
            conn.commit()
        if result.rowcount == 0:
            return jsonify({'error': 'Record not found or not authorized to update.'}), 404
        return jsonify({'message': 'Record updated successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Delete a blood oxygen record
@app.route('/blood-oxygen/<int:record_id>', methods=['DELETE'])
@token_required
def delete_blood_oxygen_record(current_user_id, record_id):
    try:
        with get_db_connection() as conn:
            result = conn.execute(
                'DELETE FROM blood_oxygen_levels WHERE id = ? AND user_id = ?',
                (record_id, current_user_id)
            )
            conn.commit()
        if result.rowcount == 0:
            return jsonify({'error': 'Record not found or not authorized to delete.'}), 404
        return jsonify({'message': 'Record deleted successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Add a new blood oxygen record
@app.route('/blood-oxygen', methods=['POST'])
@token_required
def add_blood_oxygen_record(current_user_id):
    data = request.json
    blood_oxygen_level = data.get('value')
    date = data.get('date')

    if not blood_oxygen_level or not date:
        return jsonify({'error': 'Blood oxygen level and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                'INSERT INTO blood_oxygen_levels (user_id, blood_oxygen_level, date) VALUES (?, ?, ?)',
                (current_user_id, blood_oxygen_level, date)
            )
            new_item_id = cursor.lastrowid
            conn.commit()
        return jsonify({'message': 'Blood oxygen level recorded successfully.', 'id': new_item_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Get all blood pressure records for a user
@app.route('/blood-pressure', methods=['GET'])
@token_required
def get_blood_pressure_records(current_user_id):
    try:
        with get_db_connection() as conn:
            records = conn.execute(
                'SELECT * FROM blood_pressure WHERE user_id = ?',
                (current_user_id,)
            ).fetchall()
        return jsonify([dict(record) for record in records]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Add a new blood pressure record
@app.route('/blood-pressure', methods=['POST'])
@token_required
def add_blood_pressure_record(current_user_id):
    data = request.json

    blood_pressure = data.get('value')
    date = data.get('date')

    if not blood_pressure or not date:
        return jsonify({'error': 'Blood pressure and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                'INSERT INTO blood_pressure (user_id, blood_pressure, date) VALUES (?, ?, ?)',
                (current_user_id, blood_pressure, date)
            )
            new_item_id = cursor.lastrowid
            conn.commit()
        return jsonify({'message': 'Blood pressure recorded successfully.', 'id': new_item_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Update a blood pressure record
@app.route('/blood-pressure/<int:record_id>', methods=['PUT'])
@token_required
def update_blood_pressure_record(current_user_id, record_id):
    data = request.json
    blood_pressure = data.get('blood_pressure')
    date = data.get('date')

    if not blood_pressure or not date:
        return jsonify({'error': 'Blood pressure and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            result = conn.execute(
                'UPDATE blood_pressure SET blood_pressure = ?, date = ? WHERE id = ? AND user_id = ?',
                (blood_pressure, date, record_id, current_user_id)
            )
            conn.commit()
        if result.rowcount == 0:
            return jsonify({'error': 'Record not found or not authorized to update.'}), 404
        return jsonify({'message': 'Record updated successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Delete a blood pressure record
@app.route('/blood-pressure/<int:record_id>', methods=['DELETE'])
@token_required
def delete_blood_pressure_record(current_user_id, record_id):
    try:
        with get_db_connection() as conn:
            result = conn.execute(
                'DELETE FROM blood_pressure WHERE id = ? AND user_id = ?',
                (record_id, current_user_id)
            )
            conn.commit()
        if result.rowcount == 0:
            return jsonify({'error': 'Record not found or not authorized to delete.'}), 404
        return jsonify({'message': 'Record deleted successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Get all blood sugar records for a user
@app.route('/blood-sugar', methods=['GET'])
@token_required
def get_blood_sugar_records(current_user_id):
    try:
        with get_db_connection() as conn:
            records = conn.execute(
                'SELECT * FROM blood_sugar WHERE user_id = ?',
                (current_user_id,)
            ).fetchall()
        return jsonify([dict(record) for record in records]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Add a new blood sugar record
@app.route('/blood-sugar', methods=['POST'])
@token_required
def add_blood_sugar_record(current_user_id):
    data = request.json
    blood_sugar = data.get('value')
    date = data.get('date')

    if not blood_sugar or not date:
        return jsonify({'error': 'Blood sugar and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                'INSERT INTO blood_sugar (user_id, blood_sugar, date) VALUES (?, ?, ?)',
                (current_user_id, blood_sugar, date)
            )
            new_item_id = cursor.lastrowid
            conn.commit()
        return jsonify({'message': 'Blood sugar recorded successfully.', 'id': new_item_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Update a blood sugar record
@app.route('/blood-sugar/<int:record_id>', methods=['PUT'])
@token_required
def update_blood_sugar_record(current_user_id, record_id):
    data = request.json
    blood_sugar = data.get('blood_sugar')
    date = data.get('date')

    if not blood_sugar or not date:
        return jsonify({'error': 'Blood sugar and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            result = conn.execute(
                'UPDATE blood_sugar SET blood_sugar = ?, date = ? WHERE id = ? AND user_id = ?',
                (blood_sugar, date, record_id, current_user_id)
            )
            conn.commit()
        if result.rowcount == 0:
            return jsonify({'error': 'Record not found or not authorized to update.'}), 404
        return jsonify({'message': 'Record updated successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Delete a blood sugar record
@app.route('/blood-sugar/<int:record_id>', methods=['DELETE'])
@token_required
def delete_blood_sugar_record(current_user_id, record_id):
    try:
        with get_db_connection() as conn:
            result = conn.execute(
                'DELETE FROM blood_sugar WHERE id = ? AND user_id = ?',
                (record_id, current_user_id)
            )
            conn.commit()
        if result.rowcount == 0:
            return jsonify({'error': 'Record not found or not authorized to delete.'}), 404
        return jsonify({'message': 'Record deleted successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Get all weight records for a user
@app.route('/weight', methods=['GET'])
@token_required
def get_weight_records(current_user_id):
    try:
        with get_db_connection() as conn:
            records = conn.execute(
                'SELECT * FROM weight WHERE user_id = ?',
                (current_user_id,)
            ).fetchall()
        return jsonify([dict(record) for record in records]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Add a new weight record
@app.route('/weight', methods=['POST'])
@token_required
def add_weight_record(current_user_id):
    data = request.json
    weight = data.get('value')
    date = data.get('date')

    if not weight or not date:
        return jsonify({'error': 'Weight and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.execute(
                'INSERT INTO weight (user_id, weight, date) VALUES (?, ?, ?)',
                (current_user_id, weight, date)
            )
            new_item_id = cursor.lastrowid
            conn.commit()
        return jsonify({'message': 'Weight recorded successfully.', 'id': new_item_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Update a weight record
@app.route('/weight/<int:record_id>', methods=['PUT'])
@token_required
def update_weight_record(current_user_id, record_id):
    data = request.json
    weight = data.get('weight')
    date = data.get('date')

    if not weight or not date:
        return jsonify({'error': 'Weight and date are required.'}), 400

    try:
        with get_db_connection() as conn:
            result = conn.execute(
                'UPDATE weight SET weight = ?, date = ? WHERE id = ? AND user_id = ?',
                (weight, date, record_id, current_user_id)
            )
            conn.commit()
        if result.rowcount == 0:
            return jsonify({'error': 'Record not found or not authorized to update.'}), 404
        return jsonify({'message': 'Record updated successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Delete a weight record
@app.route('/weight/<int:record_id>', methods=['DELETE'])
@token_required
def delete_weight_record(current_user_id, record_id):
    try:
        with get_db_connection() as conn:
            result = conn.execute(
                'DELETE FROM weight WHERE id = ? AND user_id = ?',
                (record_id, current_user_id)
            )
            conn.commit()
        if result.rowcount == 0:
            return jsonify({'error': 'Record not found or not authorized to delete.'}), 404
        return jsonify({'message': 'Record deleted successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

# ssl_context=('cert.pem', 'key.pem')
