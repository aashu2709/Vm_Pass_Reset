from flask import Flask, request, render_template, jsonify
import subprocess
import os
import re   # <-- regex import (for validation)

app = Flask(__name__)

# 🔹 Password validation helper function
def validate_password(password: str) -> str:
    """Returns error message if password invalid, else empty string."""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return ""

# Route for the main page (form)
@app.route('/')
def index():
    return render_template('index.html')

# Route to reset password
@app.route('/reset_password', methods=['POST'])
def reset_password():
    vm_ip = request.form['vm_ip']
    username = request.form['username']
    old_password = request.form['old_password']
    new_password = request.form['new_password']

    # ✅ Use the helper here
    error_msg = validate_password(new_password)
    if error_msg:
        return jsonify({'error': error_msg}), 400
    
    # Basic password strength check
    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters long!'}), 400
    
    try:
        # Call PowerShell script with admin credentials from environment variables
        admin_user = os.environ['ADMIN_USER']
        admin_pass = os.environ['ADMIN_PASS']  # Set in environment variables
        result = subprocess.run(
    [
        "powershell.exe", "-File", "reset_password.ps1",
        vm_ip, username, old_password, new_password, admin_user
    ],
    input=admin_pass,  # sends password via stdin
    capture_output=True,
    text=True
)
        
        if result.returncode == 0:
            return jsonify({'message': 'Password reset successfully!'})
        else:
            # Extract the first line of stderr for a cleaner error
            error_lines = result.stderr.strip().splitlines()
            # Find the line that starts with "Error:"
            user_error = next((line for line in error_lines if line.startswith("Error:")), error_lines[0] if error_lines else "Failed to reset password!")
            return jsonify({'error': user_error}), 400
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # Use HTTPS in production