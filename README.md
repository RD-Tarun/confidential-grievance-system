# Confidential Grievance System

A secure grievance submission portal designed to ensure that user complaints remain private, tamper-proof, and accessible only to authorized administrators.

This project demonstrates the use of modern cybersecurity concepts such as encryption, OTP-based authentication, and digital signatures in a simple grievance management workflow.

---

## Features

- Secure user registration and login using hashed passwords (bcrypt)
- OTP-based verification to prevent unauthorized access
- Confidential grievance submission using AES encryption
- RSA encryption for secure key exchange
- Digital signatures to ensure grievance integrity
- Admin-only grievance viewing and verification
- SQLite database for lightweight storage

---

## Security Mechanisms Used

### Password Protection
- User passwords are never stored in plaintext.
- Passwords are hashed using `bcrypt`.

### OTP Authentication
- A One-Time Password is generated during login.
- OTP expires after a short time window to prevent replay attacks.

### Confidentiality (Encryption)
- Grievances are encrypted using AES symmetric encryption.
- The AES key is protected using RSA public key encryption.

### Integrity (Digital Signatures)
- Each grievance is digitally signed using RSA.
- Admin verifies the signature before trusting the complaint content.

---

## Project Files

| File | Purpose |
|------|---------|
| `app.py` | Main Flask application backend |
| `grievance.db` | SQLite database storing users and encrypted grievances |
| `admin_public.pem` | RSA public key used for encryption and verification |
| `admin_private.pem` | RSA private key used for decryption (must be kept secret) |

---

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/confidential-grievance-system.git
cd confidential-grievance-system
```

2. Install Dependencies
```
pip install flask pycryptodome bcrypt
```

3. Run the Application
```
python app.py
```

The server will start on:
```
http://127.0.0.1:5000/
```
