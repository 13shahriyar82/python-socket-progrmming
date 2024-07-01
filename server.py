import socket
import threading
import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

users = {}
active_users = {}
keys = {}
file_transfer_requests = {}

def encrypt_message(key, message):
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'0123456789abcdef'), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + ' ' * (16 - len(message) % 16)
    encrypted_message = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted_message).decode()

def decrypt_message(key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message)
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'0123456789abcdef'), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode().strip()

def handle_client(client_socket, client_address):
    username = None
    try:
        data = client_socket.recv(1024).decode()
        command = data.split()[0]
        
        if command == 'Registration':
            username = data.split()[1]
            password = data.split()[2]
            if username in users:
                client_socket.send('USERNAME_TAKEN'.encode())
            else:
                users[username] = hashlib.sha256(password.encode()).hexdigest()
                client_socket.send('REGISTER_SUCCESS'.encode())
        
        elif command == 'Login':
            username = data.split()[1]
            password = client_socket.recv(1024).decode().split()[2]
            if username not in users or users[username] != hashlib.sha256(password.encode()).hexdigest():
                client_socket.send('LOGIN_FAIL'.encode())
            else:
                if username in active_users:
                    active_users[username].close()
                active_users[username] = client_socket
                session_key = os.urandom(16)
                keys[username] = session_key
                encrypted_key = encrypt_message(password.encode()[:16], session_key.hex())
                client_socket.send(f'Key {encrypted_key}'.encode())
                
                handle_hello(client_socket, username)
                
                while True:
                    encrypted_message = client_socket.recv(1024).decode()
                    if not encrypted_message:
                        break
                    message = decrypt_message(keys[username], encrypted_message)
                    handle_message(client_socket, username, message)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        if username and username in active_users:
            del active_users[username]
            del keys[username]
            broadcast_message(f'{username} left the chat room.', exclude=username)

def handle_hello(client_socket, username):
    welcome_message = f'Hi {username}, welcome to the chat room.'
    client_socket.send(encrypt_message(keys[username], welcome_message).encode())
    broadcast_message(f'{username} join the chat room.', exclude=username)

def broadcast_message(message, exclude=None):
    for user, user_socket in active_users.items():
        if user != exclude:
            user_socket.send(encrypt_message(keys[user], message).encode())

def handle_message(client_socket, username, message):
    if message.startswith('Please send the list of attendees'):
        users_list = ','.join(active_users.keys())
        client_socket.send(encrypt_message(keys[username], f'Here is the list of attendees:\n{users_list}').encode())
    elif message.startswith('Public message'):
        msg_len = int(message.split('=')[1].split(':')[0])
        msg_body = message.split(':')[1].strip()
        broadcast_message(f'Public message from {username}, length={msg_len}:\n{msg_body}')
    elif message.startswith('Private message'):
        parts = message.split(':')[0].split(' ')
        recipients = parts[5].split(',')
        msg_len = int(parts[3].split('=')[1])
        msg_body = message.split(':')[1].strip()
        for recipient in recipients:
            if recipient in active_users:
                active_users[recipient].send(encrypt_message(keys[recipient], f'Private message, length={msg_len} from {username} to {",".join(recipients)}:\n{msg_body}').encode())
    elif message.startswith('File transfer request'):
        parts = message.split(':')
        recipient = parts[1].split()[1]
        file_info = parts[2].split(',')
        file_name = file_info[0].strip()
        file_size = int(file_info[1].strip())
        file_transfer_requests[recipient] = {'sender': username, 'file_name': file_name, 'file_size': file_size}
        if recipient in active_users:
            active_users[recipient].send(encrypt_message(keys[recipient], f'File transfer request, from {username}: {file_name}, {file_size}').encode())
    elif message.startswith('File transfer response'):
        parts = message.split(':')
        recipient = parts[1].split()[1]
        response = parts[2].strip()
        if recipient in active_users:
            active_users[recipient].send(encrypt_message(keys[recipient], f'File transfer response, from {username}: {response}').encode())
    elif message.startswith('File transfer'):
        parts = message.split(':')
        recipient = parts[1].split()[1]
        part_number = int(parts[1].split()[3])
        data = parts[2].strip()
        if recipient in active_users:
            active_users[recipient].send(encrypt_message(keys[recipient], f'File transfer, part {part_number}, from {username}: {data}').encode())
    elif message.startswith('Tagged message'):
        parts = message.split(':')
        recipient = parts[1].split()[1]
        tag = parts[2].strip()
        message_body = parts[3].strip()
        if recipient in active_users:
            active_users[recipient].send(encrypt_message(keys[recipient], f'Tagged message, from {username}, {tag}: {message_body}').encode())
    elif message.startswith('Bye'):
        client_socket.close()
        if username in active_users:
            del active_users[username]
            del keys[username]
            broadcast_message(f'{username} left the chat room.')
    else:
        client_socket.send(encrypt_message(keys[username], 'ERROR,Unknown command').encode())

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 15000))
    server.listen(5)
    print('Server listening on port 15000')
    
    while True:
        client_socket, client_address = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()

start_server()
