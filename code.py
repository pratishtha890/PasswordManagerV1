from flask import Flask, render_template, request, flash
import os
import hashlib
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Constants
HASH_NAME = 'sha256'
ITERATIONS = 100000
SALT_SIZE = 16

# Functions for hashing
def generate_salt():
    return os.urandom(SALT_SIZE)

def hash_password(password, salt):
    password = password.encode('utf-8')
    dk = hashlib.pbkdf2_hmac(HASH_NAME, password, salt, ITERATIONS)
    return dk

def store_password(password):
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    salt_encoded = base64.b64encode(salt).decode('utf-8')
    hash_encoded = base64.b64encode(hashed_password).decode('utf-8')
    with open('passwords.txt', 'a') as f:
        f.write(f"{password},{salt_encoded},{hash_encoded}\n")
    return salt_encoded, hash_encoded

def verify_password(stored_salt, stored_hash, password_to_check):
    salt = base64.b64decode(stored_salt)
    hash_ = base64.b64decode(stored_hash)
    hashed_password_to_check = hash_password(password_to_check, salt)
    return hashed_password_to_check == hash_

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        password = request.form['password']
        action = request.form['action']

        if action == 'Store':
            stored_salt, stored_hash = store_password(password)
            flash(f"Password Stored. Salt: {stored_salt}, Hash: {stored_hash}")
        elif action == 'Verify':
            stored_salt = request.form['salt']
            stored_hash = request.form['hash']
            if verify_password(stored_salt, stored_hash, password):
                flash("Password verified successfully!")
            else:
                flash("Password verification failed!")

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
