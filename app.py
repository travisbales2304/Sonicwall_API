import os
import json
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from SonicwallAPI import SonicwallAPI, SonicwallAPIError
from packaging import version

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session tracking
TEMPLATE_STORE = 'templates_store'
DEFAULT_TEMPLATE_FILE = os.path.join(TEMPLATE_STORE, 'default_template.txt')

if not os.path.exists(TEMPLATE_STORE):
    os.makedirs(TEMPLATE_STORE)

def get_api_credentials():
    creds = session.get('api_credentials', {})
    host = str(creds.get('host') or '')
    port = str(creds.get('port') or '')
    username = str(creds.get('username') or '')
    password = str(creds.get('password') or '')
    if not all([host, port, username, password]):
        raise ValueError('Missing API credentials in session.')
    return host, port, username, password

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
            firewall = SonicwallAPI(str(ip_address or ''), str(port or ''), str(username or ''), str(password or ''))
            firewall.authenticate()

            session['logged_in'] = True
            session['api_credentials'] = {
                'host': str(ip_address or ''),
                'port': str(port or ''),
                'username': str(username or ''),
                'password': str(password or '')
            }
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
    config_differences = None
    return render_template('management.html', config_differences=config_differences)

@app.route('/push_base_config', methods=['POST'])
def push_base_config():
    if 'logged_in' in session:
        try:
            host, port, username, password = get_api_credentials()
            firewall = SonicwallAPI(host, port, username, password)
            # Placeholder: Implement push_base_configuration method in SonicwallAPI if needed
            # result = firewall.push_base_configuration()
            return 'push_base_configuration not implemented', 501
            # return redirect(url_for('management'))
        except Exception as e:
            return f"Error: {str(e)}"
    return redirect(url_for('login'))

@app.route('/compare_config', methods=['POST'])
def compare_config():
    if 'logged_in' in session:
        return redirect(url_for('config_check'))
    return redirect(url_for('login'))

@app.route('/config_builder', methods=['GET'])
def config_builder():
    # If a template is specified, load it for editing
    template_name = request.args.get('template')
    admin_defaults = {
        'firewall_name': 'Default Name',
        'http_port': 80,
        'https_port': 443,
        'idle_logout_time': 20
    }
    zones_defaults = {}
    template_data = None
    if template_name:
        template_path = os.path.join(TEMPLATE_STORE, f'{template_name}.json')
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                template_data = json.load(f)
    # List all templates for the picker
    templates = [f[:-5] for f in os.listdir(TEMPLATE_STORE) if f.endswith('.json')]
    return render_template('config_builder.html',
        admin=(template_data['administration'] if template_data and 'administration' in template_data else admin_defaults),
        zones=(template_data['zones'] if template_data and 'zones' in template_data else zones_defaults),
        template_name=template_name or '',
        templates=templates,
        template_data=template_data or {}
    )

@app.route('/edit_template/<template_name>', methods=['GET'])
def edit_template(template_name):
    return redirect(url_for('config_builder', template=template_name))

@app.route('/save_template', methods=['POST'])
def save_template():
    template_name = request.form.get('template_name')
    if not template_name:
        flash('Template name is required!', 'danger')
        return redirect(url_for('config_builder'))
    # Build config dict from form (expand this as needed for all sections)
    config = {
        'administration': {
            'firewall_name': request.form.get('firewall_name'),
            'http_port': int(request.form.get('http_port', 80)),
            'https_port': int(request.form.get('https_port', 443)),
            'idle_logout_time': int(request.form.get('idle_logout_time', 20))
        },
        'zones': {},
        # Address Objects and other sections should be parsed and added here
    }
    # Parse address objects from dynamic form fields
    address_objects = []
    for key in request.form:
        if key.startswith('addr_name_'):
            idx = key.split('_')[-1]
            obj = {
                'name': request.form.get(f'addr_name_{idx}'),
                'type': request.form.get(f'addr_type_{idx}'),
                'zone': request.form.get(f'addr_zone_{idx}'),
                'host_ip': request.form.get(f'addr_ip_{idx}'),
                'range_begin': request.form.get(f'addr_range_begin_{idx}'),
                'range_end': request.form.get(f'addr_range_end_{idx}'),
                'subnet': request.form.get(f'addr_subnet_{idx}'),
                'mask': request.form.get(f'addr_mask_{idx}')
            }
            address_objects.append(obj)
    if address_objects:
        config['address_objects'] = address_objects
    
    # Parse zones from dynamic form fields
    zones = {}
    for key in request.form:
        if key.startswith('zone_name_'):
            idx = key.split('_')[-1]
            zone_name = request.form.get(f'zone_name_{idx}')
            if zone_name:  # Only add if zone name is provided
                zones[zone_name] = {
                    'gateway_anti_virus': bool(request.form.get(f'zone_{idx}_gateway_anti_virus')),
                    'intrusion_prevention': bool(request.form.get(f'zone_{idx}_intrusion_prevention')),
                    'anti_spyware': bool(request.form.get(f'zone_{idx}_anti_spyware')),
                    'app_control': bool(request.form.get(f'zone_{idx}_app_control')),
                    'dpi_ssl_client': bool(request.form.get(f'zone_{idx}_dpi_ssl_client')),
                    'dpi_ssl_server': bool(request.form.get(f'zone_{idx}_dpi_ssl_server')),
                    'create_group_vpn': bool(request.form.get(f'zone_{idx}_create_group_vpn')),
                    'ssl_control': bool(request.form.get(f'zone_{idx}_ssl_control')),
                    'sslvpn_access': bool(request.form.get(f'zone_{idx}_sslvpn_access'))
                }
    if zones:
        config['zones'] = zones
    
    # Parse interfaces from dynamic form fields
    interfaces = []
    for key in request.form:
        if key.startswith('iface_name_'):
            idx = key.split('_')[-1]
            iface = {
                'name': request.form.get(f'iface_name_{idx}'),
                'zone': request.form.get(f'iface_zone_{idx}'),
                'ip_assignment_mode': request.form.get(f'iface_ip_assignment_mode_{idx}'),
                'ip': request.form.get(f'iface_ip_{idx}'),
                'netmask': request.form.get(f'iface_netmask_{idx}'),
                'gateway': request.form.get(f'iface_gateway_{idx}'),
                'dhcp_hostname': request.form.get(f'iface_dhcp_hostname_{idx}')
            }
            interfaces.append(iface)
    if interfaces:
        config['interfaces'] = interfaces
    filename = os.path.join(TEMPLATE_STORE, f'{template_name}.json')
    with open(filename, 'w') as f:
        json.dump(config, f, indent=2)
    flash(f'Template "{template_name}" saved!', 'success')
    return redirect(url_for('config_builder'))

@app.route('/select_default_template', methods=['GET', 'POST'])
def select_default_template():
    templates = [f for f in os.listdir(TEMPLATE_STORE) if f.endswith('.json')]
    current_default = None
    if os.path.exists(DEFAULT_TEMPLATE_FILE):
        with open(DEFAULT_TEMPLATE_FILE, 'r') as f:
            current_default = f.read().strip()
    if request.method == 'POST':
        selected = request.form.get('default_template')
        if selected:
            with open(DEFAULT_TEMPLATE_FILE, 'w') as f:
                f.write(selected)
            flash(f'Default template set to {selected}', 'success')
        return redirect(url_for('select_default_template'))
    return render_template('select_default_template.html', templates=templates, current_default=current_default)

# Update config_check to use the selected default template if available
@app.route('/config_check')
def config_check():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    try:
        host, port, username, password = get_api_credentials()
        firewall = SonicwallAPI(host, port, username, password)
        results = []
        # Load default template if available
        default_template = None
        if os.path.exists(DEFAULT_TEMPLATE_FILE):
            with open(DEFAULT_TEMPLATE_FILE, 'r') as f:
                default_template_name = f.read().strip()
            template_path = os.path.join(TEMPLATE_STORE, default_template_name)
            if os.path.exists(template_path):
                with open(template_path, 'r') as f:
                    default_template = json.load(f)
        # Administration
        try:
            admin_actual = firewall.get_configure_administration()
            print(f"DEBUG - Full admin response: {admin_actual}")
            
            if default_template and 'administration' in default_template:
                admin_expected = default_template['administration']
            else:
                admin_expected = {
                    'firewall_name': 'Default Name',
                    'http_port': 80,
                    'https_port': 443,
                    'idle_logout_time': 20
                }
            
            admin_section = {'name': 'Administration', 'matches': True, 'items': []}
            for key, expected in admin_expected.items():
                actual = admin_actual.get('administration', {}).get(key)
                print(f"DEBUG - Key: {key}, Expected: {expected}, Actual: {actual}")
                match = (actual == expected)
                admin_section['items'].append({'key': key, 'expected': expected, 'actual': actual, 'match': match})
                if not match:
                    admin_section['matches'] = False
            results.append(admin_section)
        except SonicwallAPIError as e:
            results.append({'name': 'Administration', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})
        # Zones
        try:
            zones_actual = firewall.get_zone_config()
            
            # Zone checking now includes granular settings verification
            # Checks for zone existence and compares all security settings against template expectations
            
            # Get expected zones from template or use default
            if default_template and 'zones' in default_template:
                zones_expected = default_template['zones']
            else:
                # Default zones to check if no template is specified
                zones_expected = {
                    'DMZ': {
                        'gateway_anti_virus': True,
                        'intrusion_prevention': True,
                        'anti_spyware': True,
                        'app_control': True,
                        'dpi_ssl_client': True,
                        'dpi_ssl_server': False,
                        'create_group_vpn': False,
                        'ssl_control': False,
                        'sslvpn_access': True
                    }
                }
            
            # Check each expected zone
            for expected_zone_name, expected_settings in zones_expected.items():
                found_zone = False
                
                for zone in zones_actual.get('zones', []):
                    name = zone.get('name')
                    if name == expected_zone_name:
                        found_zone = True
                        section = {'name': f'Zone: {name}', 'matches': True, 'items': []}
                        
                        # Check zone existence
                        section['items'].append({'key': 'exists', 'expected': True, 'actual': True, 'match': True})
                        
                        # Check each security setting
                        for setting_key, expected_value in expected_settings.items():
                            actual_value = zone.get(setting_key, False)
                            match = (actual_value == expected_value)
                            section['items'].append({
                                'key': setting_key.replace('_', ' ').title(), 
                                'expected': expected_value, 
                                'actual': actual_value, 
                                'match': match
                            })
                            if not match:
                                section['matches'] = False
                        
                        results.append(section)
                        break
                
                if not found_zone:
                    results.append({'name': f'Zone: {expected_zone_name}', 'matches': False, 'items': [{'key': 'exists', 'expected': True, 'actual': False, 'match': False}]})
            
            # Also show all zones that exist on the firewall (for informational purposes)
            all_zones_found = []
            for zone in zones_actual.get('zones', []):
                zone_name = zone.get('name', 'Unknown')
                all_zones_found.append(zone_name)
            
            if all_zones_found:
                # Add a summary of all zones found
                results.append({
                    'name': 'All Zones Found', 
                    'matches': True, 
                    'items': [{
                        'key': 'zones', 
                        'expected': 'List of all zones', 
                        'actual': ', '.join(all_zones_found), 
                        'match': True
                    }]
                })
        except SonicwallAPIError as e:
            results.append({'name': 'Zones', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Address Objects (dynamic, from template)
        try:
            addr_actual = firewall.get_address_object_config()
            addr_expected_list = default_template.get('address_objects', []) if default_template else []
            for addr_expected in addr_expected_list:
                found = False
                for obj in addr_actual.get('address_objects', []):
                    ipv4 = obj.get('ipv4', {})
                    if ipv4.get('name') == addr_expected['name']:
                        found = True
                        section = {'name': 'Address Object: ' + addr_expected['name'], 'matches': True, 'items': []}
                        for key in ['zone', 'type']:
                            actual = ipv4.get(key)
                            expected = addr_expected.get(key)
                            match = (actual == expected)
                            section['items'].append({'key': key, 'expected': expected, 'actual': actual, 'match': match})
                            if not match:
                                section['matches'] = False
                        # For network type, check subnet/mask
                        if addr_expected.get('type') == 'network':
                            network = ipv4.get('network', {})
                            for key in ['subnet', 'mask']:
                                actual = network.get(key)
                                expected = addr_expected.get(key)
                                match = (actual == expected)
                                section['items'].append({'key': key, 'expected': expected, 'actual': actual, 'match': match})
                                if not match:
                                    section['matches'] = False
                        results.append(section)
                if not found:
                    results.append({'name': 'Address Object: ' + addr_expected['name'], 'matches': False, 'items': [{'key': 'exists', 'expected': True, 'actual': False, 'match': False}]})
        except SonicwallAPIError as e:
            results.append({'name': 'Address Objects', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Groups
        try:
            groups_actual = firewall.get_groups_config()
            group_expected = {'name': '*GRP - Syntrio Public'}
            found = False
            for group in groups_actual.get('address_groups', []):
                ipv4 = group.get('ipv4', {})
                if ipv4.get('name') == group_expected['name']:
                    found = True
                    results.append({'name': 'Address Group: ' + group_expected['name'], 'matches': True, 'items': [{'key': 'exists', 'expected': True, 'actual': True, 'match': True}]})
            if not found:
                results.append({'name': 'Address Group: ' + group_expected['name'], 'matches': False, 'items': [{'key': 'exists', 'expected': True, 'actual': False, 'match': False}]})
        except SonicwallAPIError as e:
            results.append({'name': 'Address Groups', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Interfaces
        try:
            iface_actual = firewall.get_interface_config()
            iface_expected = {'name': 'X0', 'zone': 'LAN'}
            found = False
            for iface in iface_actual.get('interfaces', []):
                ipv4 = iface.get('ipv4', {})
                if ipv4.get('name') == iface_expected['name']:
                    found = True
                    section = {'name': 'Interface: ' + iface_expected['name'], 'matches': True, 'items': []}
                    actual_zone = ipv4.get('ip_assignment', {}).get('zone')
                    match = (actual_zone == iface_expected['zone'])
                    section['items'].append({'key': 'zone', 'expected': iface_expected['zone'], 'actual': actual_zone, 'match': match})
                    if not match:
                        section['matches'] = False
                    results.append(section)
            if not found:
                results.append({'name': 'Interface: ' + iface_expected['name'], 'matches': False, 'items': [{'key': 'exists', 'expected': True, 'actual': False, 'match': False}]})
        except SonicwallAPIError as e:
            results.append({'name': 'Interfaces', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # DHCP Server
        try:
            dhcp_actual = firewall.get_dhcp_server_config()
            dhcp_enabled = dhcp_actual.get('dhcp_server', {}).get('ipv4', {}).get('enable')
            results.append({'name': 'DHCP Server', 'matches': dhcp_enabled is True, 'items': [{'key': 'enabled', 'expected': True, 'actual': dhcp_enabled, 'match': dhcp_enabled is True}]})
        except SonicwallAPIError as e:
            results.append({'name': 'DHCP Server', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Access Rules
        try:
            access_actual = firewall.get_access_rules_config()
            access_rules = access_actual.get('access_rules', [])
            results.append({'name': 'Access Rules', 'matches': len(access_rules) > 0, 'items': [{'key': 'count', 'expected': '>0', 'actual': len(access_rules), 'match': len(access_rules) > 0}]})
        except SonicwallAPIError as e:
            results.append({'name': 'Access Rules', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Anti-Spam
        try:
            anti_spam_actual = firewall.get_anti_spam_config()
            anti_spam_enabled = anti_spam_actual.get('anti_spam', {}).get('enable')
            results.append({'name': 'Anti-Spam', 'matches': anti_spam_enabled is True, 'items': [{'key': 'enabled', 'expected': True, 'actual': anti_spam_enabled, 'match': anti_spam_enabled is True}]})
        except SonicwallAPIError as e:
            msg = str(e)
            if 'E_UNLICENSED' in msg or 'Licensing must be activated' in msg:
                results.append({'name': 'Anti-Spam', 'matches': False, 'items': [{'key': 'unlicensed', 'expected': 'Licensed', 'actual': 'Unlicensed: cannot check', 'match': False}]})
            else:
                results.append({'name': 'Anti-Spam', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': msg, 'match': False}]})

        # Realtime Blacklisting
        try:
            rbl_actual = firewall.get_realtime_blacklisting_config()
            rbl_enabled = rbl_actual.get('rbl', {}).get('enable')
            results.append({'name': 'Realtime Blacklisting', 'matches': rbl_enabled is True, 'items': [{'key': 'enabled', 'expected': True, 'actual': rbl_enabled, 'match': rbl_enabled is True}]})
        except SonicwallAPIError as e:
            results.append({'name': 'Realtime Blacklisting', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Service Objects
        try:
            svc_obj_actual = firewall.get_service_object_config()
            svc_obj_count = len(svc_obj_actual.get('service_objects', []))
            results.append({'name': 'Service Objects', 'matches': svc_obj_count > 0, 'items': [{'key': 'count', 'expected': '>0', 'actual': svc_obj_count, 'match': svc_obj_count > 0}]})
        except SonicwallAPIError as e:
            results.append({'name': 'Service Objects', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Service Groups
        try:
            svc_grp_actual = firewall.get_service_group_config()
            svc_grp_count = len(svc_grp_actual.get('service_groups', []))
            results.append({'name': 'Service Groups', 'matches': svc_grp_count > 0, 'items': [{'key': 'count', 'expected': '>0', 'actual': svc_grp_count, 'match': svc_grp_count > 0}]})
        except SonicwallAPIError as e:
            results.append({'name': 'Service Groups', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Device Info
        try:
            dev_info = firewall.get_device_info()
            results.append({'name': 'Device Info', 'matches': 'error' not in dev_info, 'items': [{'key': 'retrieved', 'expected': True, 'actual': 'error' not in dev_info, 'match': 'error' not in dev_info}]})
        except SonicwallAPIError as e:
            results.append({'name': 'Device Info', 'matches': False, 'items': [{'key': 'error', 'expected': 'Available', 'actual': str(e), 'match': False}]})

        # Remove debug printing
        return render_template('config_check.html', results=results)
    except Exception as e:
        import traceback
        print('Error in /config_check:', e)
        traceback.print_exc()
        return f"Internal Server Error: {e}", 500

@app.route('/fix_configuration', methods=['POST'])
def fix_configuration():
    if 'logged_in' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    
    try:
        data = request.get_json()
        fix_type = data.get('fix_type')
        new_value = data.get('new_value')
        
        if not fix_type or new_value is None:
            return jsonify({'success': False, 'error': 'Missing fix_type or new_value'}), 400
        
        host, port, username, password = get_api_credentials()
        firewall = SonicwallAPI(host, port, username, password)
        
        if fix_type == 'firewall_name':
            # Update firewall name
            result = firewall.update_firewall_name(new_value)
        elif fix_type == 'http_port':
            # Update HTTP port
            result = firewall.update_http_port(int(new_value))
        elif fix_type == 'https_port':
            # Update HTTPS port
            result = firewall.update_https_port(int(new_value))
        elif fix_type == 'idle_logout_time':
            # Update idle logout time
            result = firewall.update_idle_logout_time(int(new_value))
        else:
            return jsonify({'success': False, 'error': f'Unsupported fix type: {fix_type}'}), 400
        
        if result.get('success', False):
            # Commit the changes
            try:
                commit_result = firewall.commit_changes()
                if 'error' in commit_result:
                    return jsonify({'success': False, 'error': f'Updated but failed to commit: {commit_result["error"]}'})
                return jsonify({'success': True, 'message': result.get('message', 'Configuration updated and committed successfully')})
            except Exception as commit_error:
                return jsonify({'success': False, 'error': f'Updated but failed to commit: {str(commit_error)}'})
        else:
            return jsonify({'success': False, 'error': result.get('error', f'Failed to update {fix_type}')})
            
    except Exception as e:
        import traceback
        print('Error in /fix_configuration:', e)
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
