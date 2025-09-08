from flask import Flask, request, render_template, jsonify
import subprocess
import os

app = Flask(__name__)

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
    
    # Basic password strength check
    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters long!'}), 400
    
    try:
        # Call PowerShell script with admin credentials from environment variables
        admin_user = os.environ.get('ADMIN_USER', 'Administrator')
        admin_pass = os.environ.get('ADMIN_PASS', 'AdminPassword123')  # Set in environment variables
        result = subprocess.run([
            'powershell.exe', '-File', 'reset_password.ps1',
            vm_ip, username, old_password, new_password, admin_user, admin_pass
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            return jsonify({'message': 'Password reset successfully!'})
        else:
            return jsonify({'error': result.stderr or 'Failed to reset password!'}), 500
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # Use HTTPS in production