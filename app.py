from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import jwt
import datetime
import os
import werkzeug.security as security

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get('JWT_SECRET', 'zaqui_gps_secret_2026')
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    # Renders PostgreSQL URLs use 'postgres://' but psycopg2 expects 'postgresql://'
    url = DATABASE_URL
    if url and url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(url)

def init_db():
    if not DATABASE_URL:
        print("No DATABASE_URL found. Skipping DB init.")
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

init_db()

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400

    hashed = security.generate_password_hash(password)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM users')
        user_count = cursor.fetchone()[0]
        is_admin = True if user_count == 0 else False

        cursor.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)',
                       (username, hashed, is_admin))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'User registered successfully'})
    except psycopg2.IntegrityError:
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, is_admin FROM users WHERE username = %s', (username,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row and security.check_password_hash(row[0], password):
            token = jwt.encode({
                'username': username,
                'is_admin': row[1],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, SECRET_KEY, algorithm='HS256')

            return jsonify({'success': True, 'token': token, 'isAdmin': row[1]})

        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/api/admin', methods=['GET'])
def admin():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'success': False, 'message': 'Missing token'}), 401

    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if not decoded.get('is_admin'):
            return jsonify({'success': False, 'message': 'Admin privilege required'}), 403

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'user_count': count})
    except jwt.ExpiredSignatureError:
        return jsonify({'success': False, 'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'message': 'Invalid token'}), 401

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
