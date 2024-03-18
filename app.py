from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort, send_file
from flask_sqlalchemy import SQLAlchemy
import hashlib
from io import BytesIO
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'secret_key'

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 3 * 1024 * 1024  # 3 MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(b'16bytesIV0123456'), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    with open(file_path, 'wb') as file:
        file.write(ciphertext)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        ciphertext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(b'16bytesIV0123456'), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

# In-memory SQLite database for simplicity
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

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
    if file and allowed_file(file.filename):
        if file.content_length > MAX_FILE_SIZE:
            flash('File size exceeds the limit of 3 MB')
            return redirect(request.url)

        username = session.get('username')
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        filename = secure_filename(file.filename)
        file_path = os.path.join(user_folder, filename)
        file.save(file_path)
        key = bytes.fromhex(session['symmetric_key'])
        encrypt_file(file_path, key)

        user = User.query.filter_by(username=session['username']).first()
        new_file = File(filename=filename, user=user)
        db.session.add(new_file)
        db.session.commit()

        return redirect(url_for('dashboard'))
    else:
        flash('File type not allowed or file size exceeded')
        return redirect(request.url)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = User.query.filter_by(username=username).first()
    user_files = user.files  # Get files associated with the current user
    
    file_data = {}
    for file in user_files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, file.filename)
        if os.path.exists(file_path):
            file_data[file.filename] = os.path.getsize(file_path)
        else:
            file_data[file.filename] = 'File not found'

    return render_template('dashboard.html', files=user_files, file_sizes=file_data)


@app.route('/download/<filename>')
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = User.query.filter_by(username=username).first()
    file = File.query.filter_by(filename=filename, user=user).first()

    if file:
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        file_path = os.path.join(user_folder, filename)
        key = bytes.fromhex(session['symmetric_key'])
        decrypted_content = decrypt_file(file_path, key)
        return send_file(BytesIO(decrypted_content), download_name=filename, as_attachment=True)
    else:
        flash('Unauthorized access or file not found')
        return redirect(url_for('dashboard'))

@app.route('/delete/<filename>')
def delete_file(filename):
    if 'username' not in session:
        flash('Please log in to delete files.')
        return redirect(url_for('login'))

    username = session['username']
    user = User.query.filter_by(username=username).first()
    file = File.query.filter_by(filename=filename, user=user).first()

    if file:
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            db.session.delete(file)  # Delete the file record from the database
            db.session.commit()
            flash('File deleted successfully.')
        else:
            flash('File not found.')
    else:
        flash('Unauthorized access or file not found.')

    return redirect(url_for('dashboard'))

@app.route('/image/<filename>')
def get_image(filename):
    if 'username' not in session:
        flash('Please log in to view images.')
        return redirect(url_for('login'))

    username = session['username']
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    file_path = os.path.join(user_folder, filename)
    if os.path.exists(file_path):
        key = bytes.fromhex(session['symmetric_key'])
        decrypted_image = decrypt_file(file_path, key)
        return send_file(BytesIO(decrypted_image), mimetype='image/jpeg')
    else:
        flash('Image not found.')
        return redirect(url_for('dashboard'))

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/logout')
def logout():
    session.clear() 
    flash('You have been logged out.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
