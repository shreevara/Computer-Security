import socket
import ssl
import hashlib
import sys

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

if __name__ == "__main__":
    # Check if the correct number of command-line arguments is provided
    if len(sys.argv) != 2:
        print("Usage: python3 serv.py <server_port>")
        sys.exit(1)

    server_port = int(sys.argv[1])

    # Create an SSL socket server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("cert.pem", "key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_domain = "remote07.cs.binghamton.edu" 

    server_ip = socket.gethostbyname(server_domain)

    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)

    print(f"Server started on {server_domain}:{server_port}")

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
