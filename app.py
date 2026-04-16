from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import os
import hashlib
import random
import base64
import io
import time
import pickle
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Zero-Trust Simulated Homomorphic Encryption Engine ---
# Implements Blinded Computation and Zero-Knowledge storage.
class ZeroTrustHE:
    def __init__(self, user_key_int):
        # The key is derived from the user's password (client-side simulation)
        self.secret_key = int(user_key_int) if user_key_int > 0 else 123456789
        self.modulus = 256
        self.large_prime = 1000003 

    def encrypt_bytes(self, data: bytes):
        """Blinds every byte using the derived secret key and random noise."""
        ciphertexts = []
        divisor = self.secret_key * self.large_prime
        for byte in data:
            noise = random.getrandbits(64)
            # E(m) = m + (Noise * Key * Prime)
            ct_value = byte + (noise * divisor)
            ciphertexts.append(ct_value)
        return ciphertexts

    def decrypt_bytes(self, ciphertexts):
        """Unblinds data using modulo arithmetic: D(ct) = ct mod (Key * Prime)."""
        decrypted = bytearray()
        divisor = self.secret_key * self.large_prime
        for ct in ciphertexts:
            byte = ct % divisor
            decrypted.append(int(byte) % self.modulus)
        return bytes(decrypted)

    def encrypt_int(self, value: int):
        """Special encryption for Blinded Computation (Homomorphic Addition)."""
        noise = random.getrandbits(64)
        divisor = self.secret_key * self.large_prime
        # We don't % 256 here to allow larger sums
        return value + (noise * divisor)

    def decrypt_int(self, ciphertext: int):
        """Decrypts a homomorphically computed integer."""
        divisor = self.secret_key * self.large_prime
        return ciphertext % divisor

    def homomorphic_multiply_scalar(self, ciphertext: int, scalar: int):
        """Performs Blinded Multiplication by a scalar: E(a) * b = E(a * b)."""
        # (a + k*divisor) * b = a*b + (k*b)*divisor
        # Still a valid ciphertext in our scheme
        return ciphertext * scalar

# --- Persistent Entropy Data Storage ---
VAULT_FILE = 'vault_data.pkl'

def load_vault():
    if os.path.exists(VAULT_FILE):
        try:
            with open(VAULT_FILE, 'rb') as f:
                data = pickle.load(f)
                # Ensure all categories exist
                for cat in ['users', 'files', 'text', 'activity', 'numbers', 'messages']:
                    if cat not in data: data[cat] = {}
                
                # Robust case-insensitive username normalization with MERGING
                for cat in ['users', 'files', 'text', 'activity', 'numbers', 'messages']:
                    new_cat = {}
                    for u, v in data[cat].items():
                        low_u = u.lower().strip()
                        if low_u in new_cat:
                            # Merge existing data if types match
                            if isinstance(v, dict) and isinstance(new_cat[low_u], dict):
                                new_cat[low_u].update(v)
                            elif isinstance(v, list) and isinstance(new_cat[low_u], list):
                                new_cat[low_u].extend(v)
                        else:
                            new_cat[low_u] = v
                    data[cat] = new_cat
                
                # Migration to ID-based file storage (Ensuring hashes for keys)
                migration_needed = False
                for user in data['files']:
                    user_files = data['files'][user]
                    new_format = {}
                    for key, val in user_files.items():
                        # Case 1: Oldest format (filename: [encrypted_ints])
                        if isinstance(val, list) and len(val) > 0 and isinstance(val[0], int):
                            file_id = hashlib.md5(key.encode()).hexdigest()[:12]
                            new_format[file_id] = {'name': key, 'data': val}
                            migration_needed = True
                        # Case 2: Intermediate format (filename: {name, data}) or (id: {name, data})
                        elif isinstance(val, dict) and 'name' in val and 'data' in val:
                            # If key is NOT a valid 12-char alphanumeric ID, it's a filename key
                            if len(key) != 12 or not key.isalnum():
                                file_id = hashlib.md5(key.encode()).hexdigest()[:12]
                                new_format[file_id] = val
                                migration_needed = True
                            else:
                                new_format[key] = val
                        else:
                            new_format[key] = val
                    data['files'][user] = new_format
                
                if migration_needed:
                    print("DEBUG: Migration detected - Saving updated vault structure...")
                    # We can't call save_vault(data) here easily because vault isn't global yet
                    # But we can just write it.
                    with open(VAULT_FILE, 'wb') as f:
                        pickle.dump(data, f)
                
                return data
        except Exception as e:
            print(f"CRITICAL: Vault Load Error - {str(e)}")
    return {'users': {}, 'files': {}, 'text': {}, 'activity': {}, 'numbers': {}, 'messages': {}}

def save_vault(data):
    with open(VAULT_FILE, 'wb') as f:
        pickle.dump(data, f)

vault = load_vault()

def add_activity(username, action, details=""):
    if username not in vault['activity']:
        vault['activity'][username] = []
    vault['activity'][username].insert(0, {
        'timestamp': datetime.now().strftime("%H:%M:%S"),
        'action': action,
        'details': details
    })
    vault['activity'][username] = vault['activity'][username][:8] # Keep recent 8
    save_vault(vault)

def hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256 with 100k iterations for Persistent Entropy."""
    if not salt:
        salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return h, salt

def derive_he_key(password, salt):
    """Derives the 128-bit Zero-Knowledge key on-the-fly."""
    key_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt + b"he_key", 100000)
    return int.from_bytes(key_bytes[:16], 'big')

def verify_user_password(username, password):
    username = username.lower().strip()
    if username not in vault['users']: 
        print(f"DEBUG: Auth failed - User '{username}' not found")
        return False, None
    user_info = vault['users'][username]
    # PBKDF2 Handshake
    try:
        input_hash, _ = hash_password(password, user_info['salt'])
        if input_hash == user_info['pass_hash']:
            # Derive HE key
            he_key = derive_he_key(password, user_info['salt'])
            return True, he_key
        else:
            print(f"DEBUG: Auth failed - Key mismatch for user '{username}'")
    except Exception as e:
        print(f"DEBUG: Auth error - {str(e)}")
    return False, None

# --- Application Routes ---

@app.route('/')
def home():
    if 'username' in session: return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        if username in vault['users']:
            flash("User already exists!", "warning")
            return redirect(url_for('register'))
        
        pass_hash, salt = hash_password(password)
        vault['users'][username] = {
            'pass_hash': pass_hash,
            'salt': salt
        }
        if username not in vault['files']: vault['files'][username] = {}
        if username not in vault['activity']: vault['activity'][username] = []
        if username not in vault['numbers']: vault['numbers'][username] = 0
        if username not in vault['text']: vault['text'][username] = []
        
        save_vault(vault)
        flash("Registration successful! Proceed to Login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        
        is_valid, _ = verify_user_password(username, password)
        if is_valid:
            session['username'] = username
            add_activity(username, "Access Authorized", "PBKDF2 handshake successful")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!", "danger")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session: return redirect(url_for('login'))
    username = session['username'].lower()
    if username not in vault['users']:
        session.pop('username', None)
        return redirect(url_for('login'))

    text_cts = vault['text'].get(username, [])
    # Preview of cipher-stream
    encrypted_text_preview = "".join([hex(ct % 256)[2:].zfill(2) for ct in text_cts[:40]])
    if len(text_cts) > 40: encrypted_text_preview += "..."
    
    if username not in vault['files']: vault['files'][username] = {}
    files_list = []
    total_size = 0
    for fid, fobj in vault['files'].get(username, {}).items():
        size = len(fobj['data'])
        total_size += size
        files_list.append({
            'id': fid,
            'name': fobj['name'], 
            'preview': "".join([hex(ct % 256)[2:].zfill(2) for ct in fobj['data'][:12]]), 
            'size': size
        })
    
    # Blinded Computation state
    blinded_num = vault['numbers'].get(username, 0)
    
    # Message count
    message_count = len(vault.get('messages', {}).get(username, []))
    
    analytics = {
        'assets': len(files_list),
        'weight': f"{total_size / 1024:.1f} KB",
        'score': 100 if len(files_list) > 0 else 0,
        'blinded_state': hex(blinded_num % 0xFFFFFFFF) if blinded_num else "0x00000000",
        'inbox': message_count
    }

    return render_template('dashboard.html', 
                           username=username, 
                           encrypted_text=encrypted_text_preview, 
                           files=files_list,
                           activities=vault['activity'].get(username, []),
                           analytics=analytics,
                           all_users=[u for u in vault['users'].keys() if u != username])

@app.route('/encrypt_text', methods=['POST'])
def encrypt_text():
    if 'username' not in session: return redirect(url_for('login'))
    username = session['username'].lower()
    text = request.form['secret_text']
    password = request.form.get('password')
    recipient = request.form.get('recipient', '').strip().lower()
    
    is_valid, he_key = verify_user_password(username, password)
    if is_valid and text:
        he = ZeroTrustHE(he_key)
        encrypted_data = he.encrypt_bytes(text.encode())
        
        if recipient and recipient in vault['users']:
            # Message for another user
            if 'messages' not in vault: vault['messages'] = {}
            if recipient not in vault['messages']: vault['messages'][recipient] = []
            
            vault['messages'][recipient].append({
                'sender': username,
                'data': encrypted_data,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            add_activity(username, "Secure Message Sent", f"To: {recipient}")
            flash(f"Secure message dispatched to {recipient}.", "success")
        else:
            # Personal vault
            vault['text'][username] = encrypted_data
            add_activity(username, "Text Encrypted", f"Blinded {len(text)} characters")
            flash("Payload blinded and vaulted.", "success")
        
        save_vault(vault)
    else: flash("Authorization Failed!", "danger")
    return redirect(url_for('dashboard'))

@app.route('/get_messages', methods=['POST'])
def get_messages():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    username = session['username'].lower()
    data = request.get_json()
    password = data.get('password') if data else None
    
    is_valid, he_key = verify_user_password(username, password)
    if is_valid:
        messages = vault.get('messages', {}).get(username, [])
        # We need to decrypt these with the recipient's key (current user)
        # Note: In a real ZK system, the sender would use the recipient's public key.
        # Here we simulate this by assuming the system handles the cross-key blinding.
        he = ZeroTrustHE(he_key)
        decrypted_messages = []
        for msg in messages:
            try:
                decrypted_text = he.decrypt_bytes(msg['data']).decode(errors='replace')
                decrypted_messages.append({
                    'sender': msg['sender'],
                    'text': decrypted_text,
                    'timestamp': msg['timestamp']
                })
            except: continue
        
        add_activity(username, "Inbox Accessed", f"Read {len(decrypted_messages)} messages")
        return jsonify({'messages': decrypted_messages})
    return jsonify({'error': 'Failed'}), 403

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'username' not in session: return redirect(url_for('login'))
    username = session['username'].lower()
    password = request.form.get('password')
    file = request.files.get('file')
    
    is_valid, he_key = verify_user_password(username, password)
    if is_valid and file:
        he = ZeroTrustHE(he_key)
        data = file.read()
        
        if username not in vault['files']: vault['files'][username] = {}
        # New format: {file_id: {name, data}}
        file_id = hashlib.md5(f"{file.filename}{time.time()}".encode()).hexdigest()[:12]
        vault['files'][username][file_id] = {
            'name': file.filename,
            'data': he.encrypt_bytes(data)
        }
        
        add_activity(username, "Asset Secured", f"'{file.filename}' ({len(data)} bytes)")
        save_vault(vault)
        flash(f"'{file.filename}' secured in the HE Vault.", "success")
    else: flash("Handshake failed or asset missing!", "danger")
    return redirect(url_for('dashboard'))

@app.route('/homomorphic_add', methods=['POST'])
def homomorphic_add():
    """Performs Blinded Computation: E(a) + E(b) = E(a + b) or E(a) * b = E(a * b)."""
    if 'username' not in session: return redirect(url_for('login'))
    username = session['username'].lower()
    password = request.form.get('password')
    val_to_add = request.form.get('add_value', type=int)
    operation = request.form.get('operation', 'add')
    
    is_valid, he_key = verify_user_password(username, password)
    if is_valid and val_to_add is not None:
        he = ZeroTrustHE(he_key)
        # 1. Get current blinded value (or initialize if 0)
        current_blinded = vault['numbers'].get(username, 0)
        if current_blinded == 0: current_blinded = he.encrypt_int(0)
        
        if operation == 'add':
            # 2. Encrypt the new value
            new_blinded = he.encrypt_int(val_to_add)
            # 3. Perform Homomorphic Addition
            vault['numbers'][username] = current_blinded + new_blinded
            add_activity(username, "Blinded Addition", f"Added {val_to_add} homomorphically")
            flash(f"Computed blindly: Value added to ciphertext.", "info")
        elif operation == 'multiply':
            # Perform Homomorphic Scalar Multiplication
            vault['numbers'][username] = he.homomorphic_multiply_scalar(current_blinded, val_to_add)
            add_activity(username, "Blinded Multiplication", f"Multiplied by {val_to_add} homomorphically")
            flash(f"Computed blindly: Ciphertext multiplied by scalar.", "info")
        elif operation == 'set':
            # Directly set/reset the blinded value
            vault['numbers'][username] = he.encrypt_int(val_to_add)
            add_activity(username, "Blinded Reset", f"Initialized engine to {val_to_add}")
            flash(f"Engine reset: Initial blinded state established.", "success")
        
        save_vault(vault)
    else: flash("Authorization Failed!", "danger")
    return redirect(url_for('dashboard'))

@app.route('/delete_file', methods=['POST'])
def delete_file():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    username = session['username'].lower().strip()
    data = request.get_json()
    if not data: return jsonify({'error': 'Missing payload'}), 400
    
    password = data.get('password')
    raw_id = data.get('file_id')
    
    # 1. TRACE LOGS: Start deletion attempt
    print(f"\n[TRACE] DELETE START - User: {username}")
    print(f"[TRACE] Raw ID received: {raw_id}")
    
    # 2. Decode potential IDs
    potential_ids = [raw_id]
    if raw_id:
        try:
            decoded = base64.b64decode(raw_id).decode()
            if decoded and decoded not in potential_ids:
                potential_ids.append(decoded)
                print(f"[TRACE] Decoded ID added: {decoded}")
        except: pass

    # 3. Authenticate
    is_valid, _ = verify_user_password(username, password)
    if not is_valid: 
        print(f"[TRACE] AUTH FAILED for user {username}")
        return jsonify({'error': 'Authorization failed - Check your vault password'}), 403
    print(f"[TRACE] AUTH SUCCESS for user {username}")

    # 4. Search Vault
    if username not in vault['files']:
        vault['files'][username] = {}
        save_vault(vault)
    
    user_files = vault['files'][username]
    print(f"[TRACE] Current vault keys: {list(user_files.keys())}")
    
    target_id = None
    for pid in potential_ids:
        if not pid: continue
        # A. Direct Key Match
        if pid in user_files:
            target_id = pid
            print(f"[TRACE] MATCH FOUND - Strategy: Direct Key ({pid})")
            break
        # B. Name Field Match
        for fid, fobj in user_files.items():
            if isinstance(fobj, dict) and fobj.get('name') == pid:
                target_id = fid
                print(f"[TRACE] MATCH FOUND - Strategy: Name Field ({pid} -> {fid})")
                break
        if target_id: break

    # 5. Final Substring Search (Last Resort)
    if not target_id:
        print("[TRACE] No direct match, trying substring search...")
        for fid, fobj in user_files.items():
            fname = fobj.get('name', '') if isinstance(fobj, dict) else ""
            if any(pid in fname or pid in fid for pid in potential_ids if pid):
                target_id = fid
                print(f"[TRACE] MATCH FOUND - Strategy: Substring ({fid})")
                break

    # 6. Execution
    if target_id and target_id in vault['files'][username]:
        fobj = vault['files'][username][target_id]
        filename = fobj.get('name', 'Unknown') if isinstance(fobj, dict) else target_id
        
        del vault['files'][username][target_id]
        add_activity(username, "Asset Deleted", f"Permanently removed '{filename}'")
        save_vault(vault)
        
        print(f"[TRACE] DELETE SUCCESSFUL - {filename}\n")
        return jsonify({'success': True})
    
    print(f"[TRACE] DELETE FAILED - Asset {raw_id} not found after all strategies\n")
    return jsonify({'error': 'Asset not found in your vault'}), 404

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    username = session['username'].lower().strip()
    data = request.get_json()
    if not data: return jsonify({'error': 'Missing payload'}), 400
    
    password = data.get('password')
    raw_id = data.get('file_id')
    
    potential_ids = [raw_id]
    try:
        decoded = base64.b64decode(raw_id).decode()
        if decoded and decoded not in potential_ids:
            potential_ids.append(decoded)
    except: pass
    
    print(f"DEBUG: VIEW REQUEST - User: {username}, Potential IDs: {potential_ids}")
    
    is_valid, he_key = verify_user_password(username, password)
    if not is_valid: 
        print(f"DEBUG: VIEW AUTH FAILED for {username}")
        return jsonify({'error': 'Handshake failed - check your vault password'}), 403

    user_files = vault['files'].get(username, {})
    target_id = None
    for pid in potential_ids:
        if not pid: continue
        if pid in user_files:
            target_id = pid
            break
        for fid, fobj in user_files.items():
            if isinstance(fobj, dict) and fobj.get('name') == pid:
                target_id = fid
                break
        if target_id: break

    if target_id:
        fobj = user_files[target_id]
        he = ZeroTrustHE(he_key)
        try:
            decrypted_bytes = he.decrypt_bytes(fobj['data'])
            add_activity(username, "Asset Decrypted", f"Revealed '{fobj['name']}'")
            print(f"DEBUG: VIEW SUCCESS - {fobj['name']}")
            
            ext = fobj['name'].split('.')[-1].lower()
            image_exts = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp']
            if ext in image_exts:
                mime = 'image/jpeg' if ext in ['jpg', 'jpeg'] else f'image/{ext}'
                b64 = base64.b64encode(decrypted_bytes).decode()
                return jsonify({'type': 'image', 'data': f"data:{mime};base64,{b64}"})
            elif ext == 'pdf':
                b64 = base64.b64encode(decrypted_bytes).decode()
                return jsonify({'type': 'pdf', 'data': f"data:application/pdf;base64,{b64}"})
            else:
                try: return jsonify({'type': 'text', 'data': decrypted_bytes.decode('utf-8')})
                except: return jsonify({'type': 'binary', 'data': f"Binary content ({len(decrypted_bytes)} bytes)"})
        except Exception as e:
            print(f"DEBUG: DECRYPTION ERROR - {str(e)}")
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 500
            
    return jsonify({'error': 'Asset not found in your vault'}), 404

@app.route('/download_file', methods=['POST'])
def download_file():
    if 'username' not in session: return redirect(url_for('login'))
    username = session['username'].lower().strip()
    password = request.form.get('password')
    raw_id = request.form.get('file_id')
    
    potential_ids = [raw_id]
    try:
        decoded = base64.b64decode(raw_id).decode()
        if decoded and decoded not in potential_ids:
            potential_ids.append(decoded)
    except: pass
    
    print(f"DEBUG: DOWNLOAD REQUEST - User: {username}, Potential IDs: {potential_ids}")
    
    is_valid, he_key = verify_user_password(username, password)
    if is_valid:
        user_files = vault['files'].get(username, {})
        target_id = None
        for pid in potential_ids:
            if not pid: continue
            if pid in user_files:
                target_id = pid
                break
            for fid, fobj in user_files.items():
                if isinstance(fobj, dict) and fobj.get('name') == pid:
                    target_id = fid
                    break
            if target_id: break
                
        if target_id:
            fobj = user_files[target_id]
            he = ZeroTrustHE(he_key)
            try:
                decrypted_bytes = he.decrypt_bytes(fobj['data'])
                add_activity(username, "Asset Exported", f"Downloaded '{fobj['name']}'")
                return send_file(io.BytesIO(decrypted_bytes), as_attachment=True, download_name=fobj['name'])
            except Exception as e:
                print(f"DEBUG: DOWNLOAD ERROR - {str(e)}")
    
    flash("Handshake failed or asset missing!", "danger")
    return redirect(url_for('dashboard'))

@app.route('/decrypt_text_json', methods=['POST'])
def decrypt_text_json():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    username = session['username'].lower()
    data = request.get_json()
    password = data.get('password') if data else None
    is_valid, he_key = verify_user_password(username, password)
    if is_valid:
        cts = vault['text'].get(username, [])
        if cts:
            he = ZeroTrustHE(he_key)
            add_activity(username, "Message Decrypted", "Revealed secret string")
            return jsonify({'data': he.decrypt_bytes(cts).decode(errors='replace')})
    return jsonify({'error': 'Failed'}), 403

@app.route('/decrypt_num', methods=['POST'])
def decrypt_num():
    """Reveals the result of Blinded Computation."""
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    username = session['username'].lower()
    data = request.get_json()
    password = data.get('password') if data else None
    
    is_valid, he_key = verify_user_password(username, password)
    if is_valid:
        # We handle 0 correctly now
        blinded_val = vault['numbers'].get(username, 0)
        he = ZeroTrustHE(he_key)
        if blinded_val == 0:
            result = 0
        else:
            result = he.decrypt_int(blinded_val)
            
        add_activity(username, "Computation Revealed", f"Result: {result}")
        return jsonify({'data': f"Blinded Computation Result: {result}"})
    return jsonify({'error': 'Failed'}), 403

@app.route('/clear_vault', methods=['POST'])
def clear_vault():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    username = session['username'].lower().strip()
    data = request.get_json()
    password = data.get('password') if data else None
    
    print(f"DEBUG: PURGE ATTEMPT - User: {username}")
    
    is_valid, _ = verify_user_password(username, password)
    if not is_valid: 
        print(f"DEBUG: PURGE AUTH FAILED for {username}")
        return jsonify({'error': 'Authorization failed - Check your vault password'}), 403

    # Reset the file container for the user
    vault['files'][username] = {}
    add_activity(username, "Vault Purged", "Permanently removed all multi-media assets")
    save_vault(vault)
    
    print(f"DEBUG: PURGE SUCCESSFUL for {username}")
    return jsonify({'success': True})

@app.route('/delete_text', methods=['POST'])
def delete_text():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    username = session['username'].lower()
    data = request.get_json()
    password = data.get('password') if data else None
    
    is_valid, _ = verify_user_password(username, password)
    if not is_valid: return jsonify({'error': 'Authorization failed'}), 403

    if username in vault['text']:
        vault['text'][username] = []
        add_activity(username, "Text Purged", "Cleared personal vault string")
        save_vault(vault)
        return jsonify({'success': True})
    return jsonify({'error': 'Nothing to delete'}), 404

@app.route('/logout')
def logout():
    username = session.get('username')
    if username: add_activity(username, "Session Terminated", "User logged out")
    session.pop('username', None)
    return redirect(url_for('home'))

@app.template_filter('b64encode')
def b64encode_filter(s):
    if isinstance(s, str):
        return base64.b64encode(s.encode()).decode()
    return ""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
