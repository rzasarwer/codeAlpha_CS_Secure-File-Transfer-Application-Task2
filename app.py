from flask import Flask, request, send_file, jsonify
from werkzeug.utils import secure_filename
import os
import hashlib
import datetime
from encryptor import Encryptorencryptor

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
audit_log = []

# Access Control
users = {
    'admin': 'adminpassword'
}

def authenticate(username, password):
    return users.get(username) == password

def log_action(action, username, filename):
    audit_log.append({
        'timestamp': datetime.datetime.now().isoformat(),
        'action': action,
        'username': username,
        'filename': filename
    })

# Integrity check
def compute_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

@app.route('/upload', methods=['POST'])
def upload_file():
    auth = request.authorization
    if not auth or not authenticate(auth.username, auth.password):
        return jsonify({'error': 'Unauthorized'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # Encrypt the file
        encryptor = Encryptor(auth.password)
        with open(filepath, 'rb') as f:
            encrypted_data = encryptor.encrypt(f.read())

        with open(filepath, 'wb') as f:
            f.write(encrypted_data)

        file_hash = compute_hash(filepath)
        log_action('upload', auth.username, filename)
        return jsonify({'message': 'File uploaded', 'hash': file_hash})

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    auth = request.authorization
    if not auth or not authenticate(auth.username, auth.password):
        return jsonify({'error': 'Unauthorized'}), 401

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404

    # Decrypt the file
    encryptor = Encryptor(auth.password)
    with open(filepath, 'rb') as f:
        encrypted_data = f.read()
        decrypted_data = encryptor.decrypt(encrypted_data)

    decrypted_path = filepath + '.decrypted'
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)

    log_action('download', auth.username, filename)
    return send_file(decrypted_path, as_attachment=True)

@app.route('/audit-log', methods=['GET'])
def get_audit_log():
    auth = request.authorization
    if not auth or not authenticate(auth.username, auth.password) or auth.username != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    return jsonify(audit_log)

#if __name__ == '__main__':
   # app.run(debug=True)
if __name__ == '__main__':
    app.run(host='0.0.0.0')
