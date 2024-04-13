import threading
import socket

host = '127.0.0.1'
port = 55559

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
nicknames = []

def broadcast(message):
    for client in clients:
        client.send(message)

def handle(client):
    while True:
        try:
            message = client.recv(1024).decode('ascii')
            broadcast(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast(f"{nickname} left the chat!".encode('ascii'))
            '''Here we used broadcast because we want other people in chat also see than specific nickname left the chat and if we want to print a message that not being available in the chat we use print method. '''
            nicknames.remove(nickname)
            break

def receive():
    while True:
        client , address = server.accept()
        print(f"connected with {str(address)}")

        client.send('NICK'.encode('ascii'))

        '''as you can see in the upper lines the send method provides the possibility to send a message to only one particular client not the others. '''

        nickname = client.recv(1024).decode('ascii')
        nicknames.append(nickname)
        clients.append(client)

        print(f"Nickname of the client is {nickname}!")
        broadcast(f'{nickname} joined the chat!'.encode('ascii'))
        client.send('connected to the server!'.encode('ascii'))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

print("server is listening...")
receive()