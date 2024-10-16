import socket
import subprocess
import os
import time
import datetime
from flask import Flask, render_template, request

# Directories and file paths
config_dir = os.path.expanduser("~/.rmsh/config/")
commandset_dir = os.path.expanduser("~/.rmsh/commandset/")
log_file = os.path.expanduser("~/.rmsh/logs/command.log")
uac_conf = os.path.join(config_dir, "uac.conf")
global_conf = os.path.join(config_dir, "global.conf")

# Create directories if they don't exist
os.makedirs(os.path.dirname(log_file), exist_ok=True)
os.makedirs(commandset_dir, exist_ok=True)

# Flask admin panel
app = Flask(__name__)

# Configurations
failed_attempts = {}
MAX_ATTEMPTS = 5  # Maximum login attempts
BLOCK_TIME = 300  # Block for 5 minutes
session_timeout = 300  # 5 minutes of inactivity

# Aliases and user permissions
aliases = {}
user_pass = {}
user_permissions = {}

# Command log function
def log_command(username, command):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, 'a') as f:
        f.write(f"[{timestamp}] User '{username}' executed '{command}'\n")

# Rate limit check
def check_rate_limit(client_ip):
    if client_ip in failed_attempts:
        attempts, block_time = failed_attempts[client_ip]
        if attempts >= MAX_ATTEMPTS:
            if time.time() - block_time < BLOCK_TIME:
                return True  # Still blocked
            else:
                failed_attempts[client_ip] = [0, 0]  # Reset attempts after block time
    return False

# Load aliases and permissions from uac.conf
def load_uac():
    with open(uac_conf, 'r') as f:
        for line in f:
            if 'alias' in line:
                user, alias_def = line.split()[1], line.split()[2]
                alias, cmd = alias_def.split("=")
                if user not in aliases:
                    aliases[user] = {}
                aliases[user][alias] = cmd.strip('"')
            else:
                username, password, perm = line.split(':')
                user_pass[username] = password
                user_permissions[username] = perm.strip().split(',')

# Load global settings from global.conf
def load_global_conf():
    if os.path.exists(global_conf):
        with open(global_conf, 'r') as f:
            for line in f:
                key, value = line.strip().split('=')
                if key == 'security_level':
                    return value
    return 'uac-p'  # Default to 'uac-p' if not set

    if os.path.exists(global_conf):
        with open(global_conf, 'r') as f:
            for line in f:
                key, value = line.strip().split('=')
                if key == 'port':
                    return value
    return 5000  # Default to 5000 if not set

# File transfer handling
def handle_file_transfer(client_socket, command):
    if command.startswith("upload"):
        filename = command.split(" ")[1]
        with open(os.path.join("uploads", filename), 'wb') as f:
            data = client_socket.recv(4096)
            f.write(data)
        client_socket.send(b"File uploaded.\n")
    elif command.startswith("download"):
        filename = command.split(" ")[1]
        with open(os.path.join("uploads", filename), 'rb') as f:
            client_socket.send(f.read())

# Command execution handler
def handle_client(client_socket, addr):
    client_socket.settimeout(session_timeout)
    client_ip = addr[0]

    if check_rate_limit(client_ip):
        client_socket.send(b"Too many attempts. Try again later.\n")
        client_socket.close()
        return

    load_uac()  # Load aliases and permissions
    security_level = load_global_conf()  # Load security level

    if security_level == 'uac-p':
        client_socket.send(b"Username: ")
        username = client_socket.recv(1024).decode('utf-8').strip()

        client_socket.send(b"Password: ")
        password = client_socket.recv(1024).decode('utf-8').strip()

        if user_pass.get(username) == password:
            client_socket.send(b'Authenticated. Enter commands:\n')
            history = []

            while True:
                try:
                    command = client_socket.recv(1024).decode('utf-8').strip()
                except socket.timeout:
                    client_socket.send(b"Session timed out.\n")
                    break

                if command == 'exit':
                    break

                if command in aliases.get(username, {}):
                    command = aliases[username][command]

                if command in user_permissions.get(username, []) or 'ALL' in user_permissions.get(username, []):
                    if command == 'history':
                        client_socket.send("\n".join(history).encode('utf-8'))
                    elif command.startswith("upload") or command.startswith("download"):
                        handle_file_transfer(client_socket, command)
                    else:
                        history.append(command)
                        log_command(username, command)
                        try:
                            result = subprocess.run([os.path.join(commandset_dir, command)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            client_socket.send(result.stdout + result.stderr)
                        except Exception as e:
                            client_socket.send(f"Error: {str(e)}\n".encode('utf-8'))
                else:
                    client_socket.send(b"Permission denied.\n")
        else:
            if client_ip not in failed_attempts:
                failed_attempts[client_ip] = [0, 0]
            failed_attempts[client_ip][0] += 1
            if failed_attempts[client_ip][0] >= MAX_ATTEMPTS:
                failed_attempts[client_ip][1] = time.time()  # Record block time
            client_socket.send(b"Authentication failed\n")

    elif security_level == 'nujc':
        client_socket.send(b"Proceed without authentication.\n")
        history = []

        while True:
            try:
                command = client_socket.recv(1024).decode('utf-8').strip()
            except socket.timeout:
                client_socket.send(b"Session timed out.\n")
                break

            if command == 'exit':
                break

            if command.startswith("upload") or command.startswith("download"):
                handle_file_transfer(client_socket, command)
            else:
                history.append(command)
                log_command("nujc_user", command)
                try:
                    result = subprocess.run([os.path.join(commandset_dir, command)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    client_socket.send(result.stdout + result.stderr)
                except Exception as e:
                    client_socket.send(f"Error: {str(e)}\n".encode('utf-8'))

    client_socket.close()

# Start the server
def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Server listening on port {port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        handle_client(client_socket, addr)

# Flask web admin panel routes
@app.route('/')
def home():
    return render_template('home.html')  # Render home.html

@app.route('/users')
def users():
    load_uac()
    users_list = [f"{user}:{pwd}" for user, pwd in user_pass.items()]
    return render_template('users.html', users=users_list)

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form['username']
    password = request.form['password']
    with open(uac_conf, 'a') as f:
        f.write(f"{username}:{password}:ALL\n")
    return "User added successfully."

@app.route('/logs')
def view_logs():
    with open(log_file, 'r') as f:
        logs = f.readlines()
    return render_template('logs.html', logs=logs)

@app.route('/update_security', methods=['POST'])
def update_security():
    security_level = request.form['security_level']
    with open(global_conf, 'w') as f:
        f.write(f"security_level={security_level}\n")
    return "Security level updated."

@app.route('/update_security_form')
def update_security_form():
    return render_template('update_security.html')  # Render form for updating security level

if __name__ == '__main__':
    # Setup wizard (runs if global.conf is missing)
    if not os.path.exists(global_conf):
        print("Starting setup wizard...")
        security_level = input("Select security level (nujc for no account, uac-p for user account/password): ").strip()
        with open(global_conf, 'w') as f:
            f.write(f"security_level={security_level}\n")
        rmsh_port = input("Enter port that rmsh server will be running in (5000 is recommended and the default): ").strip()
        with open(global_conf, 'w') as f:
            f.write(f"port={rmsh_port}\n")
        print("Setup complete.")

    # Start the rmsh server on a specified port
    start_server(rmsh_port)
    
    # Start the Flask admin panel
    app.run(host='0.0.0.0', port=8081)  # Runs on port 8081