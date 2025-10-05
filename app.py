# app.py

from flask import Flask, redirect, url_for, session, request, jsonify, abort
import requests
from oauthlib.oauth2 import WebApplicationClient
import os
from flask_cors import CORS
import logging
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pymysql
from database import get_db
import json
import uuid
from datetime import datetime, timedelta
import bcrypt
import jwt
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8080")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwtsecretkey")

CORS(app, resources={
    r"/*": {"origins": ["https://wheel-app-five.vercel.app", "http://localhost:8080"], "supports_credentials": True}
})

GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow HTTP (localhost)

client = WebApplicationClient(GOOGLE_CLIENT_ID)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def verify_jwt():
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        return None, 401
    token = auth.split(' ')[1]
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None, 401
    except jwt.InvalidTokenError:
        return None, 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM spin_user_tokens WHERE token = %s AND revoked = 0 AND expires_at > NOW()", (token,))
    token_info = cursor.fetchone()
    cursor.close()
    conn.close()
    if not token_info:
        return None, 401
    if token_info[0] != data['user_id']:
        return None, 401
    return data, 200

@app.route("/refresh_token", methods=["POST"])
def refresh_token():
    data = request.json
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "Missing refresh token"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM spin_user_tokens WHERE refresh_token = %s AND revoked = 0 AND expires_at > NOW()", (refresh_token,))
    token_info = cursor.fetchone()
    if not token_info:
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    user_id = token_info[0]
    cursor.execute("SELECT email, name FROM Spin_users WHERE id = %s", (user_id,))
    user_info = cursor.fetchone()
    if not user_info:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404

    email, name = user_info
    new_token = jwt.encode({
        'user_id': user_id,
        'email': email,
        'name': name,
        'exp': datetime.utcnow() + timedelta(days=7)
    }, SECRET_KEY, algorithm='HS256')

    new_refresh_token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=30)
    cursor.execute("""
        INSERT INTO spin_user_tokens (user_id, token, refresh_token, expires_at)
        VALUES (%s, %s, %s, %s)
    """, (user_id, new_token, new_refresh_token, expires_at))
    cursor.execute("UPDATE spin_user_tokens SET revoked = 1 WHERE refresh_token = %s", (refresh_token,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "token": new_token, "refresh_token": new_refresh_token})


@app.route("/")
def index():
    user_email = session.get("email")
    if user_email:
        return f"<h2>Hello, {user_email}!</h2><br><a href='/logout'>Logout</a>"
    return "<a href='/login'>Login with Google</a>"

@app.route("/login")
def login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url.replace("login", "callback"),
        scope=["openid", "email", "profile", "https://www.googleapis.com/auth/spreadsheets.readonly"],
    )
    return redirect(request_uri)

@app.route("/connect_google")
def connect_google():
    user_data, status = verify_jwt()
    if status != 200:
        return redirect(url_for('login'))
    state = jwt.encode({
        'user_id': user_data['user_id'],
        'type': 'connect',
        'exp': datetime.utcnow() + timedelta(minutes=10)
    }, SECRET_KEY, algorithm='HS256')

    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url.replace("connect_google", "callback"),
        scope=["openid", "email", "profile", "https://www.googleapis.com/auth/spreadsheets.readonly"],
        state=state
    )
    return redirect(request_uri)


@app.route("/callback")
def callback():
    logger.debug("Callback route hit")
    code = request.args.get("code")
    logger.debug(f"Received code: {code}")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    if token_response.status_code != 200:
        logger.error(f"Token request failed: {token_response.text}")
        return redirect("http://localhost:8080/?error=token_failed")
    token_data = token_response.json()
    client.parse_request_body_response(token_response.text)

    session['access_token'] = token_data['access_token']
    session['refresh_token'] = token_data.get('refresh_token')
    session['id_token'] = token_data['id_token']

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    userinfo = userinfo_response.json()

    session["email"] = userinfo.get("email")
    session["name"] = userinfo.get("name")
    session["picture"] = userinfo.get("picture")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (session["email"],))
    user = cursor.fetchone()
    if not user:
        cursor.execute("INSERT INTO Spin_users (email, name, picture) VALUES (%s, %s, %s)", 
                       (session["email"], session["name"], session["picture"]))
        conn.commit()
        cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (session["email"],))
        user = cursor.fetchone()

    # Generate JWT token
    token = jwt.encode({
        'user_id': user[0],
        'email': session["email"],
        'name': session["name"],
        'exp': datetime.utcnow() + timedelta(days=7)
    }, SECRET_KEY, algorithm='HS256')

    refresh_token_str = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=30)

    # Store token in database
    cursor.execute("""
        INSERT INTO spin_user_tokens (user_id, token, refresh_token, expires_at)
        VALUES (%s, %s, %s, %s)
    """, (user[0], token, refresh_token_str, expires_at))
    conn.commit()
    
    cursor.close()
    conn.close()

    logger.debug(f"Session after login: {session}")
    logger.debug("Redirecting to React app")

    return redirect(f"{FRONTEND_URL}/?token={token}&refresh_token={refresh_token_str}")

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "Missing username, email, or password"}), 400

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM spin_user_credentials WHERE email = %s OR username = %s", (email, username))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({"error": "Email or username already exists"}), 400

    cursor.execute("INSERT INTO Spin_users (email, name) VALUES (%s, %s)", (email, username))
    user_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO spin_user_credentials (user_id, username, email, password_hash)
        VALUES (%s, %s, %s, %s)
    """, (user_id, username, email, password_hash))
    
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True})

@app.route("/login_email", methods=["POST"])
def login_email():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, password_hash FROM spin_user_credentials WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid email or password"}), 401

    cursor.execute("SELECT email, name FROM Spin_users WHERE id = %s", (user[0],))
    user_info = cursor.fetchone()

    session["email"] = user_info[0]
    session["name"] = user_info[1]
    session["picture"] = None

    # Generate JWT token
    token = jwt.encode({
        'user_id': user[0],
        'email': user_info[0],
        'name': user_info[1],
        'exp': datetime.utcnow() + timedelta(days=7)
    }, SECRET_KEY, algorithm='HS256')

    refresh_token_str = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=30)

    cursor.execute("""
        INSERT INTO spin_user_tokens (user_id, token, refresh_token, expires_at)
        VALUES (%s, %s, %s, %s)
    """, (user[0], token, refresh_token_str, expires_at))
    conn.commit()

    cursor.close()
    conn.close()
    
    return jsonify({
        "success": True, 
        "email": user_info[0], 
        "name": user_info[1],
        "token": token,
        "refresh_token": refresh_token_str
    })

@app.route("/profile")
def profile():
    if "email" not in session:
        return redirect(url_for("index"))
    return f"""
    <h1>Profile</h1>
    <p>Email: {session['email']}</p>
    <p>Name: {session.get('name')}</p>
    <img src="{session.get('picture')}" width="100"><br>
    <a href='/logout'>Logout</a>
    """

@app.route("/user")
def get_user():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, last_wheel_id FROM Spin_users WHERE email = %s", (user_data['email'],))
    user_result = cursor.fetchone()
    
    if not user_result:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    user_id = user_result[0]
    last_wheel_id = user_result[1]
    current_wheel = None
    
    if last_wheel_id:
        cursor.execute("SELECT title, description, entries FROM spin_wheels WHERE id = %s", (last_wheel_id,))
        wheel = cursor.fetchone()
        if wheel:
            cursor.execute("SELECT settings FROM spin_wheel_settings WHERE wheel_id = %s", (last_wheel_id,))
            settings_row = cursor.fetchone()
            settings = json.loads(settings_row[0]) if settings_row else None
            cursor.execute("SELECT image_url, image_type FROM spin_wheel_images WHERE wheel_id = %s", (last_wheel_id,))
            images = cursor.fetchall()
            current_wheel = {
                "title": wheel[0],
                "description": wheel[1],
                "entries": json.loads(wheel[2]),
                "settings": settings,
                "images": [{"url": img[0], "type": img[1]} for img in images]
            }
    cursor.close()
    conn.close()
    
    return jsonify({
        "email": user_data['email'],
        "name": user_data['name'],
        "picture": session.get('picture'),
        "current_wheel": current_wheel
    })

@app.route("/advanced_settings", methods=["GET"])
def get_advanced_settings():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (user_data['email'],))
    user_result = cursor.fetchone()
    if not user_result:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    user_id = user_result[0]
    cursor.execute("SELECT is_advanced, advanced_entries FROM spin_user_advanced_settings WHERE user_id = %s", (user_id,))
    settings = cursor.fetchone()
    
    result = {
        "is_advanced": settings[0] if settings else False,
        "advanced_entries": json.loads(settings[1]) if settings and settings[1] else []
    }
    
    cursor.close()
    conn.close()
    return jsonify(result)

@app.route("/advanced_settings", methods=["POST"])
def save_advanced_settings():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json
    is_advanced = data.get("is_advanced", False)
    advanced_entries = data.get("advanced_entries", [])
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (user_data['email'],))
    user_result = cursor.fetchone()
    if not user_result:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    user_id = user_result[0]
    
    cursor.execute("SELECT id FROM spin_user_advanced_settings WHERE user_id = %s", (user_id,))
    existing = cursor.fetchone()
    
    if existing:
        cursor.execute("""
            UPDATE spin_user_advanced_settings 
            SET is_advanced = %s, advanced_entries = %s, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = %s
        """, (is_advanced, json.dumps(advanced_entries) if advanced_entries else None, user_id))
    else:
        cursor.execute("""
            INSERT INTO spin_user_advanced_settings (user_id, is_advanced, advanced_entries)
            VALUES (%s, %s, %s)
        """, (user_id, is_advanced, json.dumps(advanced_entries) if advanced_entries else None))
    
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True})

@app.route("/wheels")
def get_wheels():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (user_data['email'],))
    user_id = cursor.fetchone()[0]
    cursor.execute("""
        SELECT w.id, w.title, w.description, w.entries, w.created_at, s.uuid
        FROM spin_wheels w
        LEFT JOIN spin_shares s ON w.id = s.wheel_id AND s.share_type IN ('public', 'public_gallery')
        WHERE w.user_id = %s ORDER BY w.updated_at DESC
    """, (user_id,))
    wheels = cursor.fetchall()
    
    wheel_data = []
    for w in wheels:
        cursor.execute("SELECT settings FROM spin_wheel_settings WHERE wheel_id = %s", (w[0],))
        settings_row = cursor.fetchone()
        settings = json.loads(settings_row[0]) if settings_row else None
        cursor.execute("SELECT image_url, image_type FROM spin_wheel_images WHERE wheel_id = %s", (w[0],))
        images = cursor.fetchall()
        wheel_data.append({
            "id": w[0],
            "title": w[1],
            "description": w[2],
            "entries": json.loads(w[3]),
            "settings": settings,
            "created_at": str(w[4]),
            "share_uuid": w[5],
            "images": [{"url": img[0], "type": img[1]} for img in images]
        })
    cursor.close()
    conn.close()
    return jsonify(wheel_data)

@app.route("/wheels", methods=["POST"])
def save_wheel():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json
    title = data.get("title")
    description = data.get("description")
    entries = data.get("entries")
    settings = data.get("settings")
    images = data.get("images")
    
    if not title or not entries:
        return jsonify({"error": "Missing data"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (user_data['email'],))
    user_id = cursor.fetchone()[0]
    cursor.execute("""
        INSERT INTO spin_wheels (user_id, title, description, entries)
        VALUES (%s, %s, %s, %s)
    """, (user_id, title, description, json.dumps(entries)))
    wheel_id = cursor.lastrowid
    
    if settings:
        cursor.execute("""
            INSERT INTO spin_wheel_settings (user_id, wheel_id, settings)
            VALUES (%s, %s, %s)
        """, (user_id, wheel_id, json.dumps(settings)))
    
    if images:
        for image in images:
            cursor.execute("""
                INSERT INTO spin_wheel_images (wheel_id, user_id, image_url, image_type)
                VALUES (%s, %s, %s, %s)
            """, (wheel_id, user_id, image["url"], image["type"]))
    
    cursor.execute("UPDATE Spin_users SET last_wheel_id = %s WHERE id = %s", (wheel_id, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True, "wheel_id": wheel_id})

@app.route("/current_wheel")
def get_current_wheel():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT last_wheel_id FROM Spin_users WHERE email = %s", (user_data['email'],))
    last_wheel_id = cursor.fetchone()[0]
    
    if not last_wheel_id:
        cursor.close()
        conn.close()
        return jsonify({"wheel": None})
    
    cursor.execute("SELECT title, description, entries FROM spin_wheels WHERE id = %s", (last_wheel_id,))
    wheel = cursor.fetchone()
    cursor.execute("SELECT settings FROM spin_wheel_settings WHERE wheel_id = %s", (last_wheel_id,))
    settings_row = cursor.fetchone()
    settings = json.loads(settings_row[0]) if settings_row else None
    cursor.execute("SELECT image_url, image_type FROM spin_wheel_images WHERE wheel_id = %s", (last_wheel_id,))
    images = cursor.fetchall()
    cursor.close()
    conn.close()
    
    if not wheel:
        return jsonify({"wheel": None})
    
    return jsonify({
        "wheel": {
            "title": wheel[0],
            "description": wheel[1],
            "entries": json.loads(wheel[2]),
            "settings": settings,
            "images": [{"url": img[0], "type": img[1]} for img in images]
        }
    })

@app.route("/update_current_wheel", methods=["POST"])
def update_current_wheel():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json
    entries = data.get("entries")
    settings = data.get("settings")
    images = data.get("images")
    
    conn = get_db()
    if conn is None:
        app.logger.error("Failed to connect to the database")
        return jsonify({"error": "Database connection failed"}), 500
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, last_wheel_id FROM Spin_users WHERE email = %s", (user_data['email'],))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        user_id = user[0]
        last_wheel_id = user[1]
        
        if not last_wheel_id:
            title = data.get("title", "Untitled Wheel")
            description = data.get("description")
            cursor.execute("""
                INSERT INTO spin_wheels (user_id, title, description, entries)
                VALUES (%s, %s, %s, %s)
            """, (user_id, title, description, json.dumps(entries) if entries else json.dumps([])))
            last_wheel_id = cursor.lastrowid
            
            if settings is not None:
                cursor.execute("""
                    INSERT INTO spin_wheel_settings (user_id, wheel_id, settings)
                    VALUES (%s, %s, %s)
                """, (user_id, last_wheel_id, json.dumps(settings)))
            
            if images:
                for image in images:
                    cursor.execute("""
                        INSERT INTO spin_wheel_images (wheel_id, user_id, image_url, image_type)
                        VALUES (%s, %s, %s, %s)
                    """, (last_wheel_id, user_id, image["url"], image["type"]))
            
            cursor.execute("UPDATE Spin_users SET last_wheel_id = %s WHERE id = %s", (last_wheel_id, user_id))
        else:
            update_fields = []
            update_values = []
            
            if entries is not None:
                update_fields.append("entries = %s")
                update_values.append(json.dumps(entries))
            if data.get("title"):
                update_fields.append("title = %s")
                update_values.append(data["title"])
            if data.get("description"):
                update_fields.append("description = %s")
                update_values.append(data["description"])
            
            if update_fields:
                update_values.append(last_wheel_id)
                cursor.execute(f"UPDATE spin_wheels SET {', '.join(update_fields)} WHERE id = %s", tuple(update_values))
            
            if settings is not None:
                cursor.execute("SELECT id FROM spin_wheel_settings WHERE wheel_id = %s", (last_wheel_id,))
                existing = cursor.fetchone()
                if existing:
                    cursor.execute("""
                        UPDATE spin_wheel_settings 
                        SET settings = %s, updated_at = CURRENT_TIMESTAMP
                        WHERE wheel_id = %s
                    """, (json.dumps(settings), last_wheel_id))
                else:
                    cursor.execute("""
                        INSERT INTO spin_wheel_settings (user_id, wheel_id, settings)
                        VALUES (%s, %s, %s)
                    """, (user_id, last_wheel_id, json.dumps(settings)))
            
            if images is not None:
                cursor.execute("DELETE FROM spin_wheel_images WHERE wheel_id = %s", (last_wheel_id,))
                for image in images:
                    cursor.execute("""
                        INSERT INTO spin_wheel_images (wheel_id, user_id, image_url, image_type)
                        VALUES (%s, %s, %s, %s)
                    """, (last_wheel_id, user_id, image["url"], image["type"]))
        
        conn.commit()
    except pymysql.MySQLError as e:
        app.logger.error(f"Database error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()
    
    return jsonify({"success": True})

@app.route('/create_shared_wheel', methods=['POST'])
def create_shared_wheel():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json
    title = data.get("title")
    description = data.get("description")
    entries = data.get("entries")
    visibility = data.get("visibility")
    settings = data.get("settings")
    images = data.get("images")
    
    if not title or not entries or not visibility:
        return jsonify({"error": "Missing data"}), 400
    
    share_uuid = str(uuid.uuid4())
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (user_data['email'],))
    user_id = cursor.fetchone()[0]
    cursor.execute("""
        INSERT INTO spin_wheels (user_id, title, description, entries)
        VALUES (%s, %s, %s, %s)
    """, (user_id, title, description if visibility == 'public_gallery' else None, json.dumps(entries)))
    wheel_id = cursor.lastrowid
    
    if settings:
        cursor.execute("""
            INSERT INTO spin_wheel_settings (user_id, wheel_id, settings)
            VALUES (%s, %s, %s)
        """, (user_id, wheel_id, json.dumps(settings)))
    
    if images:
        for image in images:
            cursor.execute("""
                INSERT INTO spin_wheel_images (wheel_id, user_id, image_url, image_type)
                VALUES (%s, %s, %s, %s)
            """, (wheel_id, user_id, image["url"], image["type"]))
    
    expires_at = datetime.now() + timedelta(days=365)
    cursor.execute("""
        INSERT INTO spin_shares (wheel_id, share_type, uuid, expires_at)
        VALUES (%s, %s, %s, %s)
    """, (wheel_id, visibility, share_uuid, expires_at))
    conn.commit()
    cursor.close()
    conn.close()
    
    share_link = f"{FRONTEND_URL}/wheel/{share_uuid}"
    return jsonify({"success": True, "share_link": share_link, "share_type": visibility})

@app.route("/get_shared_wheel/<string:uuid>")
def get_shared_wheel(uuid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT w.id, w.title, w.description, w.entries, s.share_type
        FROM spin_shares s
        JOIN spin_wheels w ON s.wheel_id = w.id
        WHERE s.uuid = %s AND (s.expires_at IS NULL OR s.expires_at > NOW())
    """, (uuid,))
    share = cursor.fetchone()
    
    if not share:
        cursor.close()
        conn.close()
        logger.error(f"No wheel found for UUID: {uuid}")
        abort(404)
    
    cursor.execute("SELECT settings FROM spin_wheel_settings WHERE wheel_id = %s", (share[0],))
    settings_row = cursor.fetchone()
    settings = json.loads(settings_row[0]) if settings_row else None
    cursor.execute("SELECT image_url, image_type FROM spin_wheel_images WHERE wheel_id = %s", (share[0],))
    images = cursor.fetchall()
    cursor.execute("UPDATE spin_shares SET views = views + 1 WHERE uuid = %s", (uuid,))
    conn.commit()
    cursor.close()
    conn.close()
    
    response = {
        "wheel_id": share[0],
        "title": share[1],
        "description": share[2],
        "entries": json.loads(share[3]),
        "settings": settings,
        "share_type": share[4],
        "images": [{"url": img[0], "type": img[1]} for img in images]
    }
    logger.debug(f"Shared wheel data for UUID {uuid}: {response}")
    return jsonify(response)


@app.route("/public_wheels")
def get_public_wheels():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT w.id, w.title, w.description, w.entries, s.views, w.created_at, u.name
        FROM spin_wheels w
        JOIN spin_shares s ON s.wheel_id = w.id
        JOIN Spin_users u ON w.user_id = u.id
        WHERE s.share_type = 'public_gallery'
        ORDER BY w.created_at DESC
    """)
    wheels = cursor.fetchall()
    wheel_data = []
    for w in wheels:
        cursor.execute("SELECT settings FROM spin_wheel_settings WHERE wheel_id = %s", (w[0],))
        settings_row = cursor.fetchone()
        settings = json.loads(settings_row[0]) if settings_row else None
        cursor.execute("SELECT image_url, image_type FROM spin_wheel_images WHERE wheel_id = %s", (w[0],))
        images = cursor.fetchall()
        wheel_data.append({
            "id": w[0],
            "name": w[1],
            "description": w[2],
            "entries": json.loads(w[3]),
            "settings": settings,
            "views": w[4],
            "created": str(w[5]),
            "creator": w[6],
            "images": [{"url": img[0], "type": img[1]} for img in images]
        })
    cursor.close()
    conn.close()
    return jsonify(wheel_data)

@app.route('/import-sheet', methods=['POST'])
def import_sheet():
    try:
        user_data, status = verify_jwt()
        if status != 200:
            return jsonify({'error': 'Not authenticated'}), 401
        
        if 'access_token' not in session:
            return jsonify({'error': 'No access token found'}), 401
        
        data = request.get_json()
        spreadsheet_id = data.get('spreadsheetId')
        sheet_range = data.get('range', 'Sheet1')
        
        if not spreadsheet_id:
            return jsonify({'error': 'spreadsheetId required'}), 400

        credentials = Credentials(
            token=session['access_token'],
            refresh_token=session.get('refresh_token'),
            id_token=session.get('id_token'),
            token_uri='https://oauth2.googleapis.com/token',
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=['https://www.googleapis.com/auth/spreadsheets.readonly']
        )

        service = build('sheets', 'v4', credentials=credentials)
        sheet = service.spreadsheets()
        result = sheet.values().get(
            spreadsheetId=spreadsheet_id,
            range=sheet_range
        ).execute()
        values = result.get('values', [])

        return jsonify({'values': values})
        
    except HttpError as e:
        logger.error(f"Google Sheets API error: {e}")
        error_details = e.error_details[0] if e.error_details else {}
        return jsonify({
            'error': f'Google Sheets API error: {error_details.get("message", str(e))}'
        }), 500
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/save_wheel_image', methods=['POST'])
def save_wheel_image():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json
    image_url = data.get("url")
    image_type = data.get("type")
    
    if not image_url or not image_type:
        return jsonify({"error": "Missing image URL or type"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, last_wheel_id FROM Spin_users WHERE email = %s", (user_data['email'],))
    user = cursor.fetchone()
    
    if not user:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    user_id = user[0]
    wheel_id = user[1]
    
    if not wheel_id:
        cursor.execute("""
            INSERT INTO spin_wheels (user_id, title, entries)
            VALUES (%s, %s, %s)
        """, (user_id, "Untitled Wheel", json.dumps([])))
        wheel_id = cursor.lastrowid
        cursor.execute("UPDATE Spin_users SET last_wheel_id = %s WHERE id = %s", (wheel_id, user_id))
    
    cursor.execute("""
        INSERT INTO spin_wheel_images (wheel_id, user_id, image_url, image_type)
        VALUES (%s, %s, %s, %s)
    """, (wheel_id, user_id, image_url, image_type))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True})

@app.route('/feedback', methods=['POST'])
def submit_feedback():
    user_data, status = verify_jwt()
    if status != 200:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json
    feedback = data.get("feedback")
    
    if not feedback:
        return jsonify({"error": "Feedback text is required"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (user_data['email'],))
    user_result = cursor.fetchone()
    
    if not user_result:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    user_id = user_result[0]
    
    cursor.execute("""
        INSERT INTO spin_user_feedback (user_id, email, feedback)
        VALUES (%s, %s, %s)
    """, (user_id, user_data['email'], feedback))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({"success": True})

@app.route("/logout")
def logout():
    # Revoke all tokens for the user
    if "email" in session:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Spin_users WHERE email = %s", (session["email"],))
        user = cursor.fetchone()
        if user:
            cursor.execute("UPDATE spin_user_tokens SET revoked = 1 WHERE user_id = %s", (user[0],))
            conn.commit()
        cursor.close()
        conn.close()
    
    session.clear()
    return redirect(f"{FRONTEND_URL}/")

if __name__ == "__main__":
    app.run(debug=True)