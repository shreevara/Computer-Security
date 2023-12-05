import sys
import socket
import ssl

def validate_user_input(server_domain, server_port):
    # Create an SSL socket client
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("cert.pem")  # Use the server's certificate

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

if __name__ == "__main__":
    # Check if the correct number of command-line arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python3 cli.py <server_domain> <server_port>")
        sys.exit(1)

    server_domain = sys.argv[1]
    server_port = int(sys.argv[2])

    validate_user_input(server_domain, server_port)
