from flask import Flask, render_template, request, session, redirect, url_for
from SonicwallAPI import SonicAPIClass, authentication
from packaging import version

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session tracking

@app.route('/')
def home():
    return render_template('home.html')  # No session reset here

@app.route('/login', methods=['GET', 'POST'])
def login():
    connection_status = None

    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        port = request.form.get('port')
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            firewall = SonicAPIClass(ip_address, port, username, password)
            connection_status = authentication(firewall)

            if "Status 200" in connection_status:
                session['logged_in'] = True
                
                device_info = firewall.get_device_info()
                if 'error' not in device_info:
                    firmware_cleaned = device_info.get('firmware_version', 'Unknown')

                    session['firmware_version'] = firmware_cleaned
                    session['model'] = device_info.get('model', 'Unknown')
                    session['device_info'] = device_info

                    # Compare cleaned firmware version numerically
                    session['is_outdated'] = version.parse(firmware_cleaned) < version.parse("7.1.3")

                return redirect(url_for('management'))

        except Exception as e:
            connection_status = f"Error: {str(e)}"

    return render_template('login.html', connection_status=connection_status)

@app.route('/disconnect')
def disconnect():
    session.clear()  # Logs out user only when they click "Disconnect"
    return redirect(url_for('home'))

@app.route('/management')
def management():
    return render_template('management.html')

@app.route('/push_base_config', methods=['POST'])
def push_base_config():
    if 'logged_in' in session:
        try:
            firewall = SonicAPIClass()  # Assuming login credentials are stored
            result = firewall.push_base_configuration()  # Call method to apply base config
            return redirect(url_for('management'))
        except Exception as e:
            return f"Error: {str(e)}"
    return redirect(url_for('login'))

@app.route('/compare_config', methods=['POST'])
def compare_config():
    if 'logged_in' in session:
        try:
            firewall = SonicAPIClass()
            differences = firewall.compare_configuration()  # Retrieve only differences
            return render_template('management.html', config_differences=differences)
        except Exception as e:
            return f"Error: {str(e)}"
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
