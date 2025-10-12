from flask import Flask, request, render_template, jsonify
import subprocess
import os
import re
import ipaddress
import shutil
import logging
from logging.handlers import RotatingFileHandler  # For file logging with rotation

# ----------------------------------------------------
# Logging configuration
# ----------------------------------------------------
# Logs to BOTH console (terminal) and file in 'logs/' folder.
# Terminal: Limited (INFO+), File: Detailed (DEBUG+).
log_dir = 'logs'  # Folder inside PasswordResetApp
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'app.log')  # Exact name from screenshot

# Console handler (limited: INFO and above only)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Changed to INFO for limited terminal output

# File handler (detailed: DEBUG and above)
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)  # 10MB per file, 5 backups
file_handler.setLevel(logging.DEBUG)  # DEBUG for full details in file

# Formatter for both (same as before: timestamp - level - message)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Root logger setup
logging.basicConfig(level=logging.DEBUG, handlers=[console_handler, file_handler])

# ----------------------------------------------------
# Load admin credentials from environment variables
# ----------------------------------------------------
# These are required for connecting to the VM.
# Keeping them in environment variables is safer than hardcoding.
try:
    ADMIN_USER = os.environ['ADMIN_USER']
    ADMIN_PASS = os.environ['ADMIN_PASS']
except KeyError:
    logging.error("ADMIN_USER or ADMIN_PASS missing in environment variables.")
    raise RuntimeError("ADMIN_USER and ADMIN_PASS must be set in environment variables")

# Initialize Flask app
app = Flask(__name__)

# ----------------------------------------------------
# Helper functions for validation and sanitization
# ----------------------------------------------------

def is_valid_ipv4(addr: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        ip = ipaddress.ip_address(addr)
        return ip.version == 4
    except ValueError:
        return False

# Username validation (letters, digits, dot, underscore, hyphen, at, backslash)
USERNAME_RE = re.compile(r'^[A-Za-z0-9._@\\-]{1,64}$')
def is_valid_username(u: str) -> bool:
    """Whitelist-based username validation (safe characters only)."""
    return bool(USERNAME_RE.fullmatch(u))

def contains_control_chars(s: str) -> bool:
    """Return True if string contains control characters (newline, tab, etc.)."""
    return any(ord(ch) < 32 for ch in s)

def validate_password(password: str) -> str:
    """
    Validate password strength.
    Returns empty string if valid, otherwise an error message.
    """
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if len(password) > 128:
        return "Password is too long (max 128 characters)."
    if contains_control_chars(password):
        return "Password contains invalid control characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return ""

def find_powershell_executable() -> str:
    """
    Locate PowerShell executable.
    Works with both Windows PowerShell (powershell.exe) and PowerShell Core (pwsh).
    """
    return shutil.which('powershell.exe') or shutil.which('pwsh') or ""

def run_reset_script(vm_ip, username, old_password, new_password, admin_user, admin_pass, timeout=30):
    """
    Securely run the PowerShell password reset script.
    - Arguments are passed as a list (avoids shell injection).
    - Admin password is sent via stdin (avoids exposure in process list). DO NOT add admin_pass to cmd list!
    - Timeout ensures the call doesn't hang indefinitely.
    """
    pwsh = find_powershell_executable()
    if not pwsh:
        raise RuntimeError("Powershell executable not found on PATH.")

    cmd = [
        pwsh, '-File', 'reset_password.ps1',
        vm_ip, username, old_password, new_password, admin_user
    ]
    # IMPORTANT: admin_pass goes ONLY to input=stdin, NOT to cmd list (that causes positional param error)

    try:
        logging.debug(f"DEBUG: Running cmd: {' '.join(cmd)}")  # DEBUG: Only to file
        result = subprocess.run(
            cmd,
            input=admin_pass + '\n',  # Add \n for ReadLine() to properly read the line
            capture_output=True,     # capture stdout and stderr
            text=True,               # treat as text instead of bytes
            timeout=timeout          # fail after X seconds
        )
        logging.debug(f"DEBUG: Script stdout: {result.stdout.strip()[:200]}...")  # DEBUG: Only to file
        logging.debug(f"DEBUG: Script stderr: {result.stderr.strip()[:200]}...")  # DEBUG: Only to file
        return result
    except subprocess.TimeoutExpired:
        raise RuntimeError("Password reset operation timed out.")

# ----------------------------------------------------
# Routes
# ----------------------------------------------------

@app.route('/')
def index():
    """Serve the frontend HTML form."""
    return render_template('index.html')

@app.route('/reset_password', methods=['POST'])
def reset_password():
    """
    Handle password reset form submission.
    Validates inputs, runs the PowerShell script,
    and returns JSON response.
    """
    # --- Step 1: Get required fields ---
    try:
        vm_ip_raw = request.form['vm_ip']
        username_raw = request.form['username']
        old_password = request.form['old_password']   # password: don't strip whitespace
        new_password = request.form['new_password']
    except KeyError:
        return jsonify({'error': 'Missing required fields.'}), 400

    # --- Step 2: Sanitize non-password fields ---
    vm_ip = vm_ip_raw.strip()
    username = username_raw.strip()

    # --- Step 3: Validate inputs ---
    if not is_valid_ipv4(vm_ip):
        return jsonify({'error': 'Invalid IPv4 address.'}), 400
    if not is_valid_username(username):
        return jsonify({'error': 'Invalid username.'}), 400
    if contains_control_chars(old_password) or contains_control_chars(new_password):
        return jsonify({'error': 'Passwords must not contain control characters.'}), 400
    if len(old_password) > 128:
        return jsonify({'error': 'Old password too long.'}), 400

    # --- Step 4: Enforce password policy ---
    pw_err = validate_password(new_password)
    if pw_err:
        return jsonify({'error': pw_err}), 400

    # --- Step 5: Run PowerShell script securely ---
    logging.info(f"Attempting password reset for user='{username}' on vm='{vm_ip}'")
    try:
        result = run_reset_script(vm_ip, username, old_password, new_password, ADMIN_USER, ADMIN_PASS, timeout=30)
    except Exception as e:
        logging.exception("Error executing reset script")
        return jsonify({'error': f'Internal error: {str(e)}'}), 500

    # --- Step 6: Handle result ---
    if result.returncode == 0:
        logging.info(f"Password reset successful for user='{username}' on vm='{vm_ip}'")
        return jsonify({'message': 'Password reset successfully!'})
    else:
        # Extract first "Error:" line if present for user-friendly message
        stderr_lines = result.stderr.strip().splitlines()
        user_error = next(
            (line for line in stderr_lines if line.lower().startswith("error")),
            stderr_lines[0] if stderr_lines else "Failed to reset password!"
        )
        clean_error = user_error.replace("Error:", "").strip()
        logging.warning(
            f"Reset failed for user='{username}' on vm='{vm_ip}'. "
            f"stderr: {result.stderr.strip()[:500]}"
        )
        return jsonify({'error': user_error}), 400

# ----------------------------------------------------
# Run development server
# ----------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)