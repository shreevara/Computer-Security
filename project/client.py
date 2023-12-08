import socket
import os
import sys
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Load bank's public key
with open("bank_public_key.pem", "rb") as key_file:
    bank_public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Generate a random symmetric key
def generate_symmetric_key():
    return os.urandom(32)  # 32 bytes for AES-256

# Encrypt data using the symmetric key
def encrypt_data(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

# Encrypt the symmetric key using the bank's public key
def encrypt_symmetric_key(key):
    return bank_public_key.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def connect_to_server(hostname, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((hostname, port))
    print("Connected to bank server")
    while True:
        
            #print(client_socket.recv(1024).decode())  # Welcome message or instructions from server
            user_id = input("Enter your ID: ")
            password = input("Enter your password: ")
            
            # Generate symmetric key and encrypt user credentials
            symmetric_key = generate_symmetric_key()
            encrypted_key = encrypt_symmetric_key(symmetric_key)
            encrypted_data = encrypt_data(symmetric_key, f"{user_id}|{password}")

            # Send encrypted symmetric key and data to server
            client_socket.send(encrypted_key)
            client_socket.send(encrypted_data)

            server_response = client_socket.recv(2048).decode()
            print(server_response)
            print("\n")

            while "incorrect" in server_response:
                user_id = input("Enter your ID: ")
                password = input("Enter your password: ")
                
                # Generate symmetric key and encrypt user credentials
                symmetric_key = generate_symmetric_key()
                encrypted_key = encrypt_symmetric_key(symmetric_key)
                encrypted_data = encrypt_data(symmetric_key, f"{user_id}|{password}")

                # Send encrypted symmetric key and data to server
                client_socket.send(encrypted_key)
                client_socket.send(encrypted_data)

                server_response = client_socket.recv(2048).decode()
                print(server_response)
                print("\n")


            if server_response == "ID and password are correct":
                while True:
                    #print(client_socket.recv(1024).decode())  # Display main menu from server
                    print("Please select one of the following actions (enter 1, 2, or 3):")
                    print("1. Transfer money")
                    print("2. Check account balance")
                    print("3. Exit")
                    option = input("Enter your choice: ")
                    client_socket.send(option.encode())

                    if option == '1':
                        while True:
                            print("Please select an account (enter 1 or 2):")
                            print("1. Savings")
                            print("2. Checking")
                            account_option = input("Enter your choice: ")
                            if not(account_option == '1' or account_option == '2'):
                                print("incorrect input")
                            else:
                                break
                        client_socket.send(account_option.encode())

                        recipient_id = input("Enter recipient's ID: ")
                        transfer_amount = float(input("Enter the amount to transfer: "))
                        recipient_info = f"{recipient_id}|{transfer_amount}"
                        client_socket.send(recipient_info.encode())

                        transfer_response = client_socket.recv(2048).decode()
                        print(transfer_response)
                        print("\n")

                    elif option == '2':
                        balance_response = client_socket.recv(2048).decode()
                        print(balance_response)

                    elif option == '3':
                        print("Exiting...\n")
                        client_socket.close()
                        sys.exit()

                    else:
                        print("Incorrect input")

            else:
                print("Authentication failed. Please try again.\n")
        
        

if __name__ == "__main__":
    bank_server_hostname = 'remote01.cs.binghamton.edu'  # Replace with actual server's hostname
    bank_server_port = 12346  # Replace with server's port number

    connect_to_server(bank_server_hostname, bank_server_port)
