from flask import Flask, request, jsonify
import hashlib, os, base64, jwt, smtplib, random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from email.mime.text import MIMEText
import mysql.connector

app = Flask(__name__)
SECRET_KEY = "supersecretjwtkey"

# ------------------ DB CONNECTION ------------------
def get_db():
    return mysql.connector.connect(
        host="switchyard.proxy.rlwy.net",
        port=51013,
        user="root",
        password="PSYCbLbIcbFldPKnlYOFJhJPoBTxJFPt",
        database="ciphersphere"
    )

# ------------------ TEMP STORAGE ------------------
otp_store = {}   # OTPs can stay in memory (short-lived)

# ------------------ HELPERS ------------------
def derive_key(master_password, salt):
    return PBKDF2(master_password, salt.encode(), dkLen=32, count=100000)

def encrypt_password(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_password(key, enc_data):
    raw = base64.b64decode(enc_data)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# ------------------ SEND OTP ------------------
@app.route("/send_otp", methods=["POST"])
def send_otp():
    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email required"}), 400

    otp = str(random.randint(100000, 999999))
    otp_store[email] = otp

    msg = MIMEText(f"Your CipherSphere OTP is: {otp}")
    msg["Subject"] = "CipherSphere Email Verification"
    msg["From"] = "ciphersphere147@gmail.com"
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login("ciphersphere147@gmail.com", os.environ.get("GMAIL_APP_PASSWORD"))
            server.send_message(msg)
        return jsonify({"message": "OTP sent successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------ VERIFY OTP ------------------
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data.get("email")
    entered_otp = data.get("otp")
    if not email or not entered_otp:
        return jsonify({"error": "Email and OTP required"}), 400
    if otp_store.get(email) == entered_otp:
        return jsonify({"message": "OTP verified successfully"})
    else:
        return jsonify({"error": "Invalid OTP"}), 400

# ------------------ SIGNUP ------------------
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    if cur.fetchone():
        conn.close()
        return jsonify({"error": "User already exists"}), 400

    salt = os.urandom(16).hex()
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    cur.execute("INSERT INTO users (email, password_hash, salt) VALUES (%s, %s, %s)",
                (email, password_hash, salt))
    conn.commit()
    conn.close()

    return jsonify({"message": "Account created successfully"})

# ------------------ LOGIN ------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data['email'], data['password']

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 400

    salt = user["salt"]
    check_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    if check_hash != user["password_hash"]:
        return jsonify({"error": "Invalid password"}), 401

    token = jwt.encode({"email": email}, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})

# ------------------ VAULT ADD ------------------
@app.route('/vault', methods=['POST'])
def add_entry():
    data = request.get_json()
    token =  request.headers.get("Authorization")
    masterPassword = data.get("masterPassword")
    site = data.get("site")
    username = data.get("username")
    password = data.get("password")

    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = decoded['email']

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT salt FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "User not found"}), 400

        key = derive_key(masterPassword, user["salt"])
        encrypted = encrypt_password(key, password)

        cur.execute("INSERT INTO vaults (email, site, username, encrypted_password) VALUES (%s, %s, %s, %s)",
                    (email, site, username, encrypted))
        conn.commit()
        conn.close()

        return jsonify({"message": "Entry saved securely"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 401

# ------------------ VAULT GET ------------------
@app.route('/vault', methods=['GET'])
def get_entries():
    token = request.headers.get("Authorization") 
    masterPassword = request.args.get("masterPassword")

    if not token:
        return jsonify({"error": "Missing token"}), 401

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = decoded['email']

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT salt FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "User not found"}), 400

        key = derive_key(masterPassword, user["salt"])

        cur.execute("SELECT site, username, encrypted_password FROM vaults WHERE email=%s", (email,))
        rows = cur.fetchall()
        conn.close()

        result = []
        for entry in rows:
            try:
                decrypted = decrypt_password(key, entry["encrypted_password"])
            except ValueError:
                return jsonify({"error": "Incorrect master password"}), 400
            result.append({
                "site": entry["site"],
                "username": entry["username"],
                "password": decrypted
            })

        return jsonify({"vault": result}), 200

    except Exception:
        return jsonify({"error": "Unauthorized"}), 401

# ------------------ MAIN ------------------
if __name__ == '__main__':
    app.run(debug=True)
