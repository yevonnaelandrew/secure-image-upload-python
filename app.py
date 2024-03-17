from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'secret_key'

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(b'16bytesIV0123456'), backend=default_backend())

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path, 'wb') as file:
        file.write(ciphertext)

# In-memory SQLite database for simplicity
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

with app.app_context():
    db.create_all()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# We generate symmetric key derived from password to encrypt images
def create_symmetric_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',  # empty salt
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        user = User.query.filter_by(username=username, password=hashed_password).first()
        if user:
            # Login successful
            session['username'] = username
            symmetric_key = create_symmetric_key(password)
            session['symmetric_key'] = symmetric_key.hex()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:
        username = session.get('username')
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username) 
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        filename = secure_filename(file.filename)
        file_path = os.path.join(user_folder, filename)
        file.save(file_path)
        key = bytes.fromhex(session['symmetric_key'])
        encrypt_file(file_path, key)
        return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    image_files = [f for f in os.listdir(user_folder) if os.path.isfile(os.path.join(user_folder, f))]
    file_sizes = {f: os.path.getsize(os.path.join(user_folder, f)) for f in image_files}
    return render_template('dashboard.html', image_files=image_files, file_sizes=file_sizes)

@app.route('/uploads/<username>/<filename>')
def download_file(username, filename):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(os.path.join(user_folder, filename)):
        abort(404)
    return send_from_directory(user_folder, filename, as_attachment=True)

@app.route('/delete/<filename>')
def delete_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    file_path = os.path.join(user_folder, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
