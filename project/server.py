import socket
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Load server's private key
with open("bank_private_key.pem", "rb") as key_file:
    server_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,  # Add password if the private key is encrypted
        backend=default_backend()
    )

# Load user passwords and balances from files
def read_passwords_file():
    passwords = {}
    with open('password.txt', 'r') as file:
        for line in file:
            user_id, password = line.strip().split()
            passwords[user_id] = password
    return passwords

def read_balance(user_id):
    with open('balance.txt', 'r') as file:
        for line in file:
            data = line.strip().split()
            if data[0] == user_id:
                return float(data[1]), float(data[2])  # Return savings and checking balances
    return None, None  # Return None if user not found

# Function to update balance in the file
def update_balance(user_id, savings_balance, checking_balance):
    updated_lines = []
    with open('balance.txt', 'r') as file:
        lines = file.readlines()

    for line in lines:
        data = line.strip().split()
        if data[0] == user_id:
            # Replace the line with updated balance
            updated_line = f"{user_id} {savings_balance} {checking_balance}\n"
            updated_lines.append(updated_line)
        else:
            updated_lines.append(line)

    # Write the updated lines back to the file
    with open('balance.txt', 'w') as file:
        file.writelines(updated_lines)


def is_recipient_valid(recipient_id):
    with open('password.txt', 'r') as file:
        for line in file:
            user_id, _ = line.strip().split()
            if user_id == recipient_id:
                return True
    return False

# Function to check if sender has sufficient funds
def has_sufficient_funds(sender_id, transfer_amount, account):
    sender_savings_balance, sender_checking_balance = read_balance(sender_id)
    # Check if the sender has enough funds in savings account (assuming only savings account is used for transfers)
    if account == '1': 
        return sender_savings_balance >= transfer_amount
    elif account == '2':
        return sender_checking_balance >= transfer_amount

# Decrypt received data using the symmetric key
def decrypt_data(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()  # Use the same padding scheme here
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()

# Process client requests
def handle_client_connection(client_socket, passwords):
    while True:
        print("hi")
        try:
            encrypted_key = client_socket.recv(2048)
            encrypted_data = client_socket.recv(2048)

            # Decrypt symmetric key using server's private key
            key = server_private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            decrypted_data = decrypt_data(key, encrypted_data)
            print("herer")
            user_id, password = decrypted_data.decode().split("|")
            print(password)
            passwords = read_passwords_file()
            print(len(passwords[user_id]))
            print(len(password))
            print(repr(password))
            if (user_id in passwords) and (passwords[user_id].strip() == password.strip()):
                client_socket.send("ID and password are correct".encode())

                while True:
                    #client_socket.send("Please select one of the following actions (enter 1, 2, or 3):\n1. Transfer money\n2. Check account balance\n3. Exit\n".encode())
                    option = client_socket.recv(1024).decode()

                    if option == '1':
                        #client_socket.send("Please select an account (enter 1 or 2):\n1. Savings\n2. Checking\n".encode())
                        account_option = client_socket.recv(1024).decode()

                        recipient_id, transfer_amount = client_socket.recv(1024).decode().split("|")
                        transfer_amount = float(transfer_amount)
                        recipient_exists = is_recipient_valid(recipient_id)
                        sufficient_funds = has_sufficient_funds(user_id, transfer_amount, account_option)

                        if recipient_exists and sufficient_funds:
                            # Update the balance file after successful transaction
                            sender_savings_balance, sender_checking_balance = read_balance(user_id)
                            recipient_savings_balance, recipient_checking_balance = read_balance(recipient_id)

                            # Deduct transfer amount from sender's account and add to recipient's account
                            if account_option == '1':
                                sender_savings_balance -= transfer_amount
                                recipient_savings_balance += transfer_amount
                            else:
                                sender_checking_balance -= transfer_amount
                                recipient_checking_balance += transfer_amount

                            # Update balances in the file
                            update_balance(user_id, sender_savings_balance, sender_checking_balance)
                            update_balance(recipient_id, recipient_savings_balance, recipient_checking_balance)

                            # Send success message to the ATM
                            client_socket.send("Your transaction is successful".encode())
                        else:
                            # Send appropriate error message to the ATM
                            if not recipient_exists:
                                client_socket.send("The recipient’s ID does not exist".encode())
                            elif not sufficient_funds:
                                client_socket.send("Your account does not have enough funds".encode())

                    elif option == '2':
                        savings_balance, checking_balance = read_balance(user_id)

                        # Format balance message to send back to ATM
                        balance_message = f"Your savings account balance: {savings_balance}\nYour checking account balance: {checking_balance}"

                        # Send account balances back to the ATM
                        client_socket.send(balance_message.encode())

                    elif option == '3':
                        client_socket.send("Exiting...".encode())
                        client_socket.close()
                        return

                    else:
                        client_socket.send("Incorrect input".encode())

            else:
                client_socket.send("ID or password is incorrect".encode())

        except Exception as e:
            print(f"Error: {e}")
            client_socket.close()
            return

def start_server(port):
    passwords = read_passwords_file()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('remote01.cs.binghamton.edu', port))
    server_socket.listen(5)

    print(f"Server listening on port {port}")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address} has been established.")
        handle_client_connection(client_socket, passwords)

if __name__ == "__main__":
    port_number = 12346  # Set your desired port number
    start_server(port_number)
