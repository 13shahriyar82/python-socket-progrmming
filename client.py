import socket
import threading
import base64
import os
from tkinter import *
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

def receive_messages(client, session_key):
    while True:
        try:
            encrypted_message = client.recv(1024).decode()
            message = decrypt_message(session_key, encrypted_message)
            chat_box.insert(END, f'{message}\n')
        except:
            break

def send_message():
    message = message_entry.get()
    if message:
        encrypted_message = encrypt_message(session_key, message)
        client.send(encrypted_message.encode())
        message_entry.delete(0, END)
        if message == 'Bye':
            client.close()
            window.quit()

def send_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        client.send(encrypt_message(session_key, f'File transfer request, to {recipient_entry.get()}: {file_name}, {file_size}').encode())

def login():
    global client, session_key
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 15000))
    client.send(f'Login {username_entry.get()} {password_entry.get()}'.encode())
    
    encrypted_key = client.recv(1024).decode().split()[1]
    session_key = bytes.fromhex(decrypt_message(password_entry.get().encode()[:16], encrypted_key))
    
    client.send(encrypt_message(session_key, f'Hello {username_entry.get()}').encode())
    
    threading.Thread(target=receive_messages, args=(client, session_key)).start()
    login_frame.pack_forget()
    chat_frame.pack()

window = Tk()
window.title("Chat Client")

login_frame = Frame(window)
Label(login_frame, text="Username:").pack(side=LEFT)
username_entry = Entry(login_frame)
username_entry.pack(side=LEFT)
Label(login_frame, text="Password:").pack(side=LEFT)
password_entry = Entry(login_frame, show="*")
password_entry.pack(side=LEFT)
Button(login_frame, text="Login", command=login).pack(side=LEFT)
login_frame.pack()

chat_frame = Frame(window)
chat_box = Text(chat_frame)
chat_box.pack()
message_entry = Entry(chat_frame)
message_entry.pack(side=LEFT)
Button(chat_frame, text="Send", command=send_message).pack(side=LEFT)
Button(chat_frame, text="Send File", command=send_file).pack(side=LEFT)
recipient_entry = Entry(chat_frame)
recipient_entry.pack(side=LEFT)
chat_frame.pack_forget()

window.mainloop()
