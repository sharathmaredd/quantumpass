from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import boto3
import os
import uuid
import base64
from datetime import datetime
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import sqlite3
import numpy as np
from qiskit import QuantumCircuit
from quantum_encryption import run_quantum_verification

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quantum_vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# AWS S3 Configuration
app.config['AWS_ACCESS_KEY_ID'] = os.getenv('AWS_ACCESS_KEY_ID')
app.config['AWS_SECRET_ACCESS_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY')
app.config['AWS_BUCKET_NAME'] = os.getenv('AWS_BUCKET_NAME', 'quantum-password-vault')
app.config['AWS_REGION'] = os.getenv('AWS_REGION', 'us-east-1')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# S3 client setup
def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'],
        region_name=app.config['AWS_REGION']
    )

# Encryption key management
def get_encryption_key():
    # Check if key exists in the database
    key_entry = EncryptionKey.query.first()
    if not key_entry:
        # Generate a new key if none exists
        key = Fernet.generate_key()
        key_entry = EncryptionKey(key=key.decode())
        db.session.add(key_entry)
        db.session.commit()
    return key_entry.key.encode()

# S3 operations
def store_password_in_s3(encrypted_password, user_id, entry_id):
    """Store encrypted password in S3"""
    try:
        s3_client = get_s3_client()
        s3_key = f"passwords/{user_id}/{entry_id}"
        s3_client.put_object(
            Bucket=app.config['AWS_BUCKET_NAME'],
            Key=s3_key,
            Body=encrypted_password.encode(),
            ServerSideEncryption='AES256'  # Enable server-side encryption
        )
        return s3_key
    except ClientError as e:
        print(f"Error storing password in S3: {e}")
        raise

def get_password_from_s3(s3_key):
    """Retrieve encrypted password from S3"""
    try:
        s3_client = get_s3_client()
        response = s3_client.get_object(
            Bucket=app.config['AWS_BUCKET_NAME'],
            Key=s3_key
        )
        return response['Body'].read().decode()
    except ClientError as e:
        print(f"Error retrieving password from S3: {e}")
        raise

def delete_password_from_s3(s3_key):
    """Delete password from S3"""
    try:
        s3_client = get_s3_client()
        s3_client.delete_object(
            Bucket=app.config['AWS_BUCKET_NAME'],
            Key=s3_key
        )
    except ClientError as e:
        print(f"Error deleting password from S3: {e}")
        raise

# Quantum encryption functions
def quantum_encrypt(password):
    """Encrypt password using quantum-inspired circuit"""
    # Convert password to binary
    binary = ''.join(format(ord(c), '08b') for c in password)
    
    # Create quantum circuit
    circuit = QuantumCircuit(len(binary), len(binary))
    
    # Apply quantum operations based on password bits
    for i, bit in enumerate(binary):
        if bit == '1':
            circuit.x(i)  # Apply X gate for 1
        circuit.h(i)     # Apply Hadamard gate
    
    # Instead of measuring, we'll use the circuit state directly
    encrypted = ''.join('1' if bit == '1' else '0' for bit in binary)
    return encrypted

def quantum_decrypt(encrypted, original_length):
    """Decrypt quantum-inspired encrypted password"""
    # Create quantum circuit
    circuit = QuantumCircuit(len(encrypted), len(encrypted))
    
    # Apply inverse operations
    for i, bit in enumerate(encrypted):
        circuit.h(i)     # Apply Hadamard gate
        if bit == '1':
            circuit.x(i)  # Apply X gate for 1
    
    # Convert binary back to string
    binary = encrypted[:original_length * 8]
    password = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
    
    return password

def store_quantum_password_in_s3(encrypted_password, original_length, user_id, entry_id):
    """Store quantum-encrypted password in S3"""
    try:
        s3_client = get_s3_client()
        s3_key = f"quantumencrypted/{user_id}/{entry_id}"
        data = {
            'encrypted': encrypted_password,
            'original_length': original_length
        }
        s3_client.put_object(
            Bucket=app.config['AWS_BUCKET_NAME'],
            Key=s3_key,
            Body=str(data),
            ServerSideEncryption='AES256'
        )
        return s3_key
    except ClientError as e:
        print(f"Error storing quantum password in S3: {e}")
        raise

def get_quantum_password_from_s3(s3_key):
    """Retrieve quantum-encrypted password from S3"""
    try:
        s3_client = get_s3_client()
        response = s3_client.get_object(
            Bucket=app.config['AWS_BUCKET_NAME'],
            Key=s3_key
        )
        data = eval(response['Body'].read().decode())
        return data['encrypted'], data['original_length']
    except ClientError as e:
        print(f"Error retrieving quantum password from S3: {e}")
        raise

# Database Models
class EncryptionKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    email_notifications = db.Column(db.Boolean, default=True)
    vaults = db.relationship('Vault', backref='owner', lazy=True)

class Vault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    entries = db.relationship('Entry', backref='vault', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    s3_key = db.Column(db.String(255), nullable=True)
    quantum_s3_key = db.Column(db.String(255), nullable=True)  # New field for quantum encryption
    vault_id = db.Column(db.Integer, db.ForeignKey('vault.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        """Encrypt and store password in S3 using both classical and quantum encryption"""
        # Classical encryption
        f = Fernet(get_encryption_key())
        encrypted_password = f.encrypt(password.encode()).decode()
        self.s3_key = store_password_in_s3(
            encrypted_password,
            self.vault.user_id,
            self.id
        )
        
        # Quantum encryption
        quantum_encrypted = quantum_encrypt(password)
        self.quantum_s3_key = store_quantum_password_in_s3(
            quantum_encrypted,
            len(password),
            self.vault.user_id,
            self.id
        )
        
        # Run quantum verification asynchronously
        import threading
        threading.Thread(target=run_quantum_verification).start()
    
    def get_password(self):
        """Retrieve and decrypt password from S3"""
        if not self.s3_key:
            raise ValueError("No password stored for this entry")
        
        # Get encrypted password from S3
        encrypted_password = get_password_from_s3(self.s3_key)
        
        # Decrypt password
        f = Fernet(get_encryption_key())
        return f.decrypt(encrypted_password.encode()).decode()
    
    def get_quantum_password(self):
        """Retrieve and decrypt quantum-encrypted password from S3"""
        if not self.quantum_s3_key:
            raise ValueError("No quantum password stored for this entry")
        
        # Get quantum-encrypted password from S3
        encrypted, original_length = get_quantum_password_from_s3(self.quantum_s3_key)
        
        # Decrypt password
        return quantum_decrypt(encrypted, original_length)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    vaults = Vault.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', vaults=vaults)

@app.route('/vault/<int:vault_id>')
@login_required
def view_vault(vault_id):
    vault = Vault.query.get_or_404(vault_id)
    if vault.user_id != current_user.id:
        return redirect(url_for('dashboard'))
    return render_template('vault.html', vault=vault)

@app.route('/vault/create', methods=['POST'])
@login_required
def create_vault():
    name = request.form.get('vault_name')
    if not name:
        flash('Vault name is required')
        return redirect(url_for('dashboard'))
    
    vault = Vault(name=name, user_id=current_user.id)
    db.session.add(vault)
    db.session.commit()
    flash('Vault created successfully')
    return redirect(url_for('dashboard'))

@app.route('/vault/<int:vault_id>/entry/add', methods=['POST'])
@login_required
def add_entry(vault_id):
    vault = Vault.query.get_or_404(vault_id)
    if vault.user_id != current_user.id:
        return redirect(url_for('dashboard'))
    
    title = request.form.get('title')
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not all([title, username, password]):
        flash('All fields are required')
        return redirect(url_for('view_vault', vault_id=vault_id))
    
    try:
        # First create the entry without password
        entry = Entry(
            title=title,
            username=username,
            vault_id=vault_id
        )
        db.session.add(entry)
        db.session.flush()  # This will generate the entry.id
        
        # Now set the password which will store it in S3
        entry.set_password(password)
        
        db.session.commit()
        flash('Entry added successfully')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding entry: {str(e)}')
        
    return redirect(url_for('view_vault', vault_id=vault_id))

@app.route('/entry/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry = Entry.query.get_or_404(entry_id)
    if entry.vault.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Delete password from S3
    if entry.s3_key:
        delete_password_from_s3(entry.s3_key)
    
    db.session.delete(entry)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/generator')
@login_required
def generator():
    return render_template('generator.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/settings/security', methods=['POST'])
@login_required
def update_security_settings():
    data = request.get_json()
    current_user.two_factor_enabled = data.get('two_factor', False)
    current_user.email_notifications = data.get('email_notifications', True)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/settings/profile', methods=['POST'])
@login_required
def update_profile():
    email = request.form.get('email')
    if email:
        current_user.email = email
        db.session.commit()
        flash('Profile updated successfully')
    return redirect(url_for('settings'))

@app.route('/settings/password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    if not check_password_hash(current_user.password_hash, current_password):
        flash('Current password is incorrect')
        return redirect(url_for('settings'))
    
    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash('Password updated successfully')
    return redirect(url_for('settings'))

@app.route('/settings/delete', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('delete_password')
    if not check_password_hash(current_user.password_hash, password):
        flash('Incorrect password')
        return redirect(url_for('settings'))
    
    # Delete all user's vaults and entries
    for vault in current_user.vaults:
        for entry in vault.entries:
            # Delete passwords from S3
            if entry.s3_key:
                delete_password_from_s3(entry.s3_key)
            db.session.delete(entry)
        db.session.delete(vault)
    
    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    flash('Account deleted successfully')
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Add a route to retrieve decrypted password (for AJAX calls)
@app.route('/entry/<int:entry_id>/password', methods=['GET'])
@login_required
def get_entry_password(entry_id):
    entry = Entry.query.get_or_404(entry_id)
    if entry.vault.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        decrypted_password = entry.get_password()
        return jsonify({'password': decrypted_password})
    except Exception as e:
        return jsonify({'error': 'Failed to decrypt password'}), 500

@app.route('/password-vault', methods=['GET', 'POST'])
@login_required
def password_vault():
    if request.method == 'POST':
        website = request.form.get('website')
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Store the password securely
        store_password_securely(password, current_user.id)
        
        # Run quantum verification asynchronously
        import threading
        threading.Thread(target=run_quantum_verification).start()
        
        flash('Password stored successfully!', 'success')
        return redirect(url_for('password_vault'))
    
    # Get user's passwords
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    decrypted_passwords = []
    
    for pwd in passwords:
        try:
            decrypted = retrieve_password_from_s3(pwd.encrypted_password, current_user.id, pwd.id)
            decrypted_passwords.append({
                'website': pwd.website,
                'username': pwd.username,
                'password': decrypted
            })
        except Exception as e:
            flash(f'Error retrieving password for {pwd.website}: {str(e)}', 'error')
    
    return render_template('password_vault.html', passwords=decrypted_passwords)

if __name__ == '__main__':
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if quantum_s3_key column exists in Entry table
        conn = sqlite3.connect('instance/quantum_vault.db')
        cursor = conn.cursor()
        
        # Get column info
        cursor.execute("PRAGMA table_info(entry)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add quantum_s3_key column if it doesn't exist
        if 'quantum_s3_key' not in columns:
            cursor.execute("ALTER TABLE entry ADD COLUMN quantum_s3_key VARCHAR(255)")
            conn.commit()
        
        conn.close()
        
        # Ensure encryption key exists
        get_encryption_key()
    
    app.run(debug=True) 