# serv.py

import socket
import ssl
import hashlib

# Define the function to validate user credentials
def validate_user(user_id, password):
    # Read "hashpasswd" file and validate credentials
    with open("hashpasswd", "r") as file:
        for line in file:
            parts = line.strip().split(' ', 2)
            if len(parts) < 3:
                continue

            stored_id, stored_password, _ = parts
            if stored_id == user_id and stored_password == hashlib.sha256(password.encode()).hexdigest():
                return True
    return False

# Create an SSL socket server
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("cert.pem", "key.pem")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Replace "remote01.cs.binghamton.edu" with your actual server's domain name
server_domain = "remote.cs.binghamton.edu"
server_port = 6599  # Replace with your port number

server_ip = socket.gethostbyname(server_domain)

server_socket.bind((server_ip, server_port))
server_socket.listen(1)

while True:
    print("Waiting for a client to connect...")
    client_socket, _ = server_socket.accept()
    ssl_client_socket = context.wrap_socket(client_socket, server_side=True)

    user_id = ssl_client_socket.recv(1024).decode()
    password = ssl_client_socket.recv(1024).decode()

    if validate_user(user_id, password):
        ssl_client_socket.send("Correct ID and password".encode())
    else:
        ssl_client_socket.send("The ID/password is incorrect".encode())

    ssl_client_socket.close()
