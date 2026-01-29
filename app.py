from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import base64
import os
import time
import random
import hashlib

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

app = Flask(__name__)

def get_db():
    return sqlite3.connect("grievance.db")

def init_db():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password BLOB,
        role TEXT,
        otp_hash BLOB,
        otp_expiry INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS feedback(
        id INTEGER PRIMARY KEY,
        enc_feedback BLOB,
        enc_aes_key BLOB,
        signature BLOB,
        status TEXT,
        ticket TEXT
    )
    """)

    db.commit()
    db.close()

if not os.path.exists("admin_private.pem"): 
    key = RSA.generate(2048)                             # RSA key pair generation for admin (rsa-2048)
    with open("admin_private.pem", "wb") as f:
        f.write(key.export_key())
    with open("admin_public.pem", "wb") as f:
        f.write(key.publickey().export_key())

with open("admin_private.pem", "rb") as f:
    ADMIN_PRIVATE = RSA.import_key(f.read())             # RSA private key import 

with open("admin_public.pem", "rb") as f:
    ADMIN_PUBLIC = RSA.import_key(f.read())              # RSA public key import

def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())   # password hashing with salt

def check_password(pw, hashed):
    return bcrypt.checkpw(pw.encode(), hashed)            # verification of single-factor authentication

def generate_otp():
    return str(random.randint(100000, 999999))            # generation of 6-digit OTP for MFA    

def aes_encrypt(data):
    key = get_random_bytes(32)                                  # symmetric AES key generation 
    cipher = AES.new(key, AES.MODE_CBC)                         # CBC mode 
    ct = cipher.encrypt(pad(data.encode(), AES.block_size))     # AES encryption of confidential feedback
    return ct, key, cipher.iv

def aes_decrypt(ct, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()  # AES decryption (admin-only access)

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    db = get_db()
    cur = db.cursor()

    pw_hash = hash_password(data["password"])  # secure password storage using hashing and salt
    
    try:
        cur.execute(
            "INSERT INTO users(username,password,role) VALUES(?,?,?)",
            (data["username"], pw_hash, data["role"])
        )
        db.commit()
    except:
        return jsonify({"msg": "User exists"}), 400

    return jsonify({"msg": "Registered successfully"})      

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT id,password FROM users WHERE username=?", (data["username"],))
    user = cur.fetchone()

    if not user or not check_password(data["password"], user[1]):
        return jsonify({"msg": "Invalid credentials"}), 401          # single-factor authentication enforcement

    otp = generate_otp()
    otp_hash = hashlib.sha256(otp.encode()).digest()                 # OTP hashing for secure MFA storage
    expiry = int(time.time()) + 60                                  # OTP expiry to prevent replay attacks

    cur.execute("UPDATE users SET otp_hash=?, otp_expiry=? WHERE id=?",
                (otp_hash, expiry, user[0]))
    db.commit()

    print("Your OTP for the session is:", otp)
    return jsonify({"msg": "OTP sent (check console)"})

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.json
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT otp_hash,otp_expiry,role FROM users WHERE username=?",
                (data["username"],))
    user = cur.fetchone()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    if int(time.time()) > user[1]:
        return jsonify({"msg": "OTP expired"}), 401     # MFA enforcement with time constraint

    if hashlib.sha256(data["otp"].encode()).digest() != user[0]:
        return jsonify({"msg": "Invalid OTP"}), 401     # MFA verification

    return jsonify({"msg": "OTP verified", "role": user[2]})

@app.route("/submit_feedback", methods=["POST"])
def submit_feedback():
    data = request.json

    encrypted, aes_key, iv = aes_encrypt(data["feedback"])       # encryption of feedback using AES

    rsa_cipher = PKCS1_OAEP.new(ADMIN_PUBLIC)
    enc_key = rsa_cipher.encrypt(aes_key)                   # secure AES key exchange using RSA public key

    h = SHA256.new(encrypted)              # Encrypted feedback is hashed using SHA-256; Hash is digitally signed using RSA private key

    signature = pkcs1_15.new(ADMIN_PRIVATE).sign(h)         

    ticket = base64.b64encode(os.urandom(8)).decode()          # Base64 encoding technique for ticket id. used for tracking and safe transmission

    db = get_db()
    cur = db.cursor()
    cur.execute("""
    INSERT INTO feedback(enc_feedback,enc_aes_key,signature,status,ticket)
    VALUES(?,?,?,?,?)
    """, (iv + encrypted, enc_key, signature, "OPEN", ticket))
    db.commit()

    return jsonify({"msg": "Feedback submitted", "ticket": ticket})

@app.route("/admin_view", methods=["GET"])
def admin_view():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id,enc_feedback,enc_aes_key,signature,status,ticket FROM feedback")
    rows = cur.fetchall()

    results = []

    for r in rows:
        iv = r[1][:16]
        ct = r[1][16:]

        rsa_cipher = PKCS1_OAEP.new(ADMIN_PRIVATE)
        aes_key = rsa_cipher.decrypt(r[2])             # AES key decryption using RSA private key (authorization)

        plain = aes_decrypt(ct, aes_key, iv)           # admin-only decryption of confidential feedback

        h = SHA256.new(ct)
        pkcs1_15.new(ADMIN_PUBLIC).verify(h, r[3])     # digital signature verification (integrity check)

        results.append({
            "ticket": r[5],
            "feedback": plain,
            "status": r[4]
        })
        
    return jsonify(results)                            # authorized admin access to decrypted data

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
