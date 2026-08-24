import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    cursor.execute("SELECT id, role FROM users WHERE username = 'admin'")
    existing_admin = cursor.fetchone()
    
    if not existing_admin:
        hashed_admin_pw = generate_password_hash("admin123")
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                       ('admin', hashed_admin_pw, 'admin'))
    elif existing_admin[1] != 'admin':
        cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
        
    conn.commit()
    conn.close()

init_db()

@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "online", "message": "ZaquiGPS™ Backend API is Running!"}), 200

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.get_json() or {}
    action = request.args.get('action', '')
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing username or password."}), 400

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    if action == 'register':
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"status": "error", "message": "Username already taken."}), 409

        role = 'admin' if username == 'admin' else 'user'
        hashed_pw = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_pw, role))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Account created successfully!", "role": role}), 201

    elif action == 'login':
        cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            return jsonify({
                "status": "success", 
                "message": "Login successful!",
                "role": user[1]
            }), 200
        else:
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401

    conn.close()
    return jsonify({"status": "error", "message": "Invalid action."}), 400

@app.route('/api/admin/users', methods=['GET'])
def get_users():
    admin_user = request.headers.get('X-Admin-User')
    if admin_user != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = [{"id": row[0], "username": row[1], "role": row[2]} for row in cursor.fetchall()]
    conn.close()
    return jsonify({"status": "success", "users": users}), 200

@app.route('/api/admin/delete', methods=['POST'])
def delete_user():
    data = request.get_json() or {}
    target_user = data.get('username')
    admin_user = request.headers.get('X-Admin-User')

    if admin_user != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    if target_user == 'admin':
        return jsonify({"status": "error", "message": "Cannot delete primary admin."}), 400

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username = ?", (target_user,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"User {target_user} deleted."}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
