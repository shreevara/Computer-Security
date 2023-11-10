# client.py

import socket
import ssl

# Create an SSL socket client
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("cert.pem")  # Use the server's certificate

server_domain = "remote.cs.binghamton.edu"  # Replace with the server's domain name
server_port = 6599  # Replace with the server's port number

def validate_user_input():
    while True:
        user_id = input("Enter your ID: ")
        password = input("Enter your password: ")

        ssl_client_socket = context.wrap_socket(socket.socket(), server_hostname=server_domain)

        try:
            ssl_client_socket.connect((server_domain, server_port))
            ssl_client_socket.send(user_id.encode())
            ssl_client_socket.send(password.encode())

            response = ssl_client_socket.recv(1024).decode()
            print(response)

            if response == "Correct ID and password":
                break  # Successful authentication
        except Exception as e:
            print(f"Error: {str(e)}")

        #print("The ID/password is incorrect. Please re-enter.")

if __name__ == "__main__":
    validate_user_input()
