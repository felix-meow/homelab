#!/usr/bin/env python3
"""
Homelab Web Dashboard
Robert Mircea
"""

from flask import Flask, render_template, request, jsonify
import subprocess
import json
import os
import tempfile
import re

app = Flask(__name__)
app.secret_key = 'homelab-secret-key-2026'

# --- Helper functions ---
def run_script(script_path, args, timeout=30):
    """Rulează un script Python și returnează output-ul"""
    cmd = ['python3', script_path] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {'success': True, 'output': result.stdout, 'error': result.stderr}
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': f'Timeout ({timeout}s)'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def get_script_path(project, script):
    """Returnează calea completă către un script"""
    return os.path.expanduser(f'~/homelab/projects/{project}/{script}')

# --- Dashboard ---
@app.route('/')
def dashboard():
    tools = [
        {'name': 'Port Scanner', 'route': '/scan', 'icon': '🔌', 'desc': 'Scanează porturi TCP'},
        {'name': 'Packet Sniffer', 'route': '/sniff', 'icon': '📡', 'desc': 'Captură pachete rețea'},
        {'name': 'File Integrity Monitor', 'route': '/monitor', 'icon': '🔒', 'desc': 'Monitorizează fișiere'},
        {'name': 'Web Vulnerability Scanner', 'route': '/vuln', 'icon': '🕷️', 'desc': 'Detectează vulnerabilități web'},
        {'name': 'Intrusion Detection System', 'route': '/ids', 'icon': '🛡️', 'desc': 'Detectează intruziuni'},
        {'name': 'Password Cracker', 'route': '/crack', 'icon': '🔑', 'desc': 'Sparge hash-uri'},
        {'name': 'Phishing Detector', 'route': '/detect', 'icon': '🎣', 'desc': 'Detectează phishing'},
        {'name': 'Firewall Simulator', 'route': '/firewall', 'icon': '🔥', 'desc': 'Simulează firewall'},
        {'name': 'Encrypted Chat', 'route': '/chat', 'icon': '💬', 'desc': 'Chat securizat'},
        {'name': 'Keylogger Detector', 'route': '/keylog', 'icon': '⌨️', 'desc': 'Detectează keylogger-i'}
    ]
    return render_template('dashboard.html', tools=tools)

# ==================== 1. PORT SCANNER ====================
@app.route('/scan')
def scan_form():
    return render_template('port_scanner.html')

@app.route('/api/scan', methods=['POST'])
def run_scan():
    data = request.get_json()
    host = data.get('host')
    ports = data.get('ports', '1-1024')
    script = get_script_path('port-scanner', 'port_scanner.py')
    result = run_script(script, ['-H', host, '-p', ports])
    return jsonify(result)

# ==================== 2. PACKET SNIFFER ====================
@app.route('/sniff')
def sniff_form():
    return render_template('packet_sniffer.html')

@app.route('/api/sniff', methods=['POST'])
def run_sniff():
    data = request.get_json()
    interface = data.get('interface', 'eth0')
    filter_str = data.get('filter', '')
    count = data.get('count', 10)
    
    script = get_script_path('packet-sniffer', 'sniffer.py')
    args = ['-i', interface, '-c', str(count)]
    if filter_str:
        args.extend(['-f', filter_str])
    
    cmd = ['sudo', '/home/roby/homelab/venv/bin/python3', script] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return jsonify({'success': True, 'output': result.stdout, 'error': result.stderr})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ==================== 3. FILE INTEGRITY MONITOR ====================
@app.route('/monitor')
def monitor_form():
    return render_template('fim.html')

@app.route('/api/monitor', methods=['POST'])
def run_monitor():
    data = request.get_json()
    directory = data.get('directory', '')
    init = data.get('init', False)
    
    script = get_script_path('file-integrity-monitor', 'fim.py')
    args = ['-d', directory]
    if init:
        args.append('--init')
    
    result = run_script(script, args, timeout=60)
    return jsonify(result)

# ==================== 4. WEB VULNERABILITY SCANNER ====================
@app.route('/vuln')
def vuln_form():
    return render_template('web_vuln.html')

@app.route('/api/vuln', methods=['POST'])
def run_vuln():
    data = request.get_json()
    url = data.get('url')
    depth = data.get('depth', 1)
    timeout = data.get('timeout', 10)
    
    script = get_script_path('web-vuln-scanner', 'scanner.py')
    result = run_script(script, ['-u', url, '-d', str(depth), '-t', str(timeout)], timeout=120)
    return jsonify(result)

# ==================== 5. INTRUSION DETECTION SYSTEM ====================
@app.route('/ids')
def ids_form():
    return render_template('ids.html')

@app.route('/api/ids', methods=['POST'])
def run_ids():
    data = request.get_json()
    interface = data.get('interface', 'eth0')
    duration = data.get('duration', 30)
    
    script = get_script_path('ids', 'ids_file.py')
    cmd = ['sudo', '/home/roby/homelab/venv/bin/python3', script, '-i', interface, '-t', str(duration)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
        return jsonify({'success': True, 'output': result.stdout, 'error': result.stderr})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ==================== 6. PASSWORD CRACKER ====================
@app.route('/crack')
def crack_form():
    return render_template('password_cracker.html')

@app.route('/api/crack', methods=['POST'])
def run_crack():
    data = request.get_json()
    target_hash = data.get('hash')
    algorithm = data.get('algorithm', 'md5')
    method = data.get('method', 'dictionary')
    wordlist = data.get('wordlist', 'wordlists/common.txt')
    max_length = data.get('max_length', 4)
    
    script = get_script_path('password-cracker', 'cracker.py')
    args = ['-t', target_hash, '-a', algorithm, '-m', method, '-w', wordlist, '-l', str(max_length)]
    result = run_script(script, args, timeout=60)
    return jsonify(result)

# ==================== 7. PHISHING DETECTOR ====================
@app.route('/detect')
def detect_form():
    return render_template('phishing_detector.html')

@app.route('/api/detect', methods=['POST'])
def run_detect():
    data = request.get_json()
    subject = data.get('subject', '')
    body = data.get('body', '')
    from_addr = data.get('from_addr', '')
    reply_to = data.get('reply_to', '')
    
    script = get_script_path('phishing-detector', 'detector.py')
    
    if from_addr or reply_to:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            email_data = {
                'subject': subject,
                'body': body,
                'headers': {'from': from_addr, 'reply-to': reply_to}
            }
            json.dump(email_data, f)
            temp_file = f.name
        result = run_script(script, ['-f', temp_file], timeout=10)
        os.unlink(temp_file)
        return jsonify(result)
    
    result = run_script(script, ['-s', subject, '-b', body], timeout=10)
    return jsonify(result)

# ==================== 8. FIREWALL SIMULATOR ====================
@app.route('/firewall')
def firewall_form():
    return render_template('firewall.html')

@app.route('/api/firewall', methods=['POST'])
def run_firewall():
    data = request.get_json()
    action = data.get('action', 'simulate')
    count = data.get('count', 20)
    
    script = get_script_path('firewall-simulator', 'firewall.py')
    
    if action == 'simulate':
        result = run_script(script, ['-s', str(count)], timeout=30)
    elif action == 'list':
        result = run_script(script, ['-l'], timeout=10)
    elif action == 'report':
        result = run_script(script, ['-R'], timeout=10)
    else:
        return jsonify({'success': False, 'error': 'Acțiune necunoscută'})
    
    return jsonify(result)

# ==================== 9. ENCRYPTED CHAT ====================
@app.route('/chat')
def chat_form():
    return render_template('encrypted_chat.html')

@app.route('/api/chat', methods=['POST'])
def run_chat():
    data = request.get_json()
    action = data.get('action')
    
    if action == 'start_server':
        script = get_script_path('encrypted-chat', 'server.py')
        cmd = ['python3', script, '--host', '0.0.0.0', '-p', '5001', '--password', 'chat123']
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return jsonify({'success': True, 'message': 'Server pornit pe port 5001'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    elif action == 'stop_server':
        try:
            subprocess.run(['pkill', '-f', 'server.py'], capture_output=True)
            return jsonify({'success': True, 'message': 'Server oprit'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    return jsonify({'success': False, 'error': 'Acțiune necunoscută'})

# ==================== 10. KEYLOGGER DETECTOR ====================
@app.route('/keylog')
def keylog_form():
    return render_template('keylogger.html')

@app.route('/api/keylog', methods=['POST'])
def run_keylog():
    script = get_script_path('keylogger-detector', 'detector.py')
    result = run_script(script, [], timeout=120)
    return jsonify(result)

# --- Run ---
if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════╗
║     🔥 Homelab Web Dashboard             ║
╠═══════════════════════════════════════════╣
║  http://localhost:5000                   ║
║  10 tools integrate                      ║
╚═══════════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)
