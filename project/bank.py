from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import socket
import pickle  # For serialization

# Load the bank server's private key
with open('bank_public.pem', 'rb') as private_file:
    bank_private_key = RSA.import_key(private_file.read())

# Load user IDs and passwords from a file
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
    with open('balances.txt', 'r') as file:
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
    with open('balances.txt', 'w') as file:
        file.writelines(updated_lines)


def is_recipient_valid(recipient_id):
    with open('passwords.txt', 'r') as file:
        for line in file:
            user_id, _ = line.strip().split()
            if user_id == recipient_id:
                return True
    return False

# Function to check if sender has sufficient funds
def has_sufficient_funds(sender_id, transfer_amount, account):
    sender_savings_balance, sender_checking_balance = read_balance(sender_id)
    # Check if the sender has enough funds in savings account (assuming only savings account is used for transfers)
    if account == 'Savings': 
        return sender_savings_balance >= transfer_amount
    elif account == 'Checkings':
        return sender_checking_balance >= transfer_amount

# Create a socket and listen for connections
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("remote00.cs.binghamton.edu", 12345))  # Replace with appropriate host and port
server_socket.listen(1)

while True:
    print("Listening for connections...")
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr} established.")

    # Receive symmetric key encrypted by client's public key
    encrypted_symmetric_key = client_socket.recv(4096)
    print(encrypted_symmetric_key)
    
    # Decrypt the symmetric key using the bank's private key
    cipher_rsa = PKCS1_OAEP.new(bank_private_key)
    try:
        symmetric_key = cipher_rsa.decrypt(encrypted_symmetric_key)
        print("Symmetric key decrypted successfully")
    except ValueError as e:
        print("Error decrypting symmetric key:", str(e))
        symmetric_key = None 
    
    # Receive encrypted ID and password using the received symmetric key
    nonce = client_socket.recv(4096)
    print(nonce)
    tag_id_password = client_socket.recv(4096)
    print(tag_id_password)
    ciphertext_id_password = client_socket.recv(4096)

    # Decrypt ID and password using the symmetric key
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    decrypted_id_password = cipher_aes.decrypt_and_verify(ciphertext_id_password, tag_id_password)
    print(decrypted_id_password)
    user_id, password = pickle.loads(decrypted_id_password)
    print(user_id)
    # Read passwords from file for authentication
    stored_passwords = read_passwords_file()

    # Authenticate user credentials
    if user_id in stored_passwords and stored_passwords[user_id] == password:
        client_socket.send(b'success')

        # Receive user's action choice (1, 2, or 3)
        received_ciphertext = client_socket.recv(4096)
        received_tag = client_socket.recv(16)

            # Decrypt the received transfer data using the symmetric key
        cipher_aes_transfer = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)  # Use the correct nonce
        decrypted_transfer_data = cipher_aes_transfer.decrypt_and_verify(received_ciphertext, received_tag)
        transfer_data = pickle.loads(decrypted_transfer_data)

            # Extract transfer details and process accordingly
        recipient_id = transfer_data['recipient_id']
        transfer_amount = transfer_data['transfer_amount']
        account = transfer_data['account']
        user_action = transfer_data['action']

        if user_action == '1':  # Option 1: Transfer money
            #recipient_and_amount = client_socket.recv(1024).decode()

            # Split the received string to get recipient_id and transfer_amount
            #recipient_id, transfer_amount = recipient_and_amount.split()
            #transfer_amount = float(transfer_amount)

            # Check recipient's ID existence and sufficient funds, update balance file
            recipient_exists = is_recipient_valid(recipient_id)
            sufficient_funds = has_sufficient_funds(user_id, transfer_amount, account)

            if recipient_exists and sufficient_funds:
                # Update the balance file after successful transaction
                sender_savings_balance, sender_checking_balance = read_balance(user_id)
                recipient_savings_balance, recipient_checking_balance = read_balance(recipient_id)

                # Deduct transfer amount from sender's account and add to recipient's account
                if account == 'Savings':
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

        elif user_action == '2':  # Option 2: Check account balance
            # Read balances from balance file
            savings_balance, checking_balance = read_balance(user_id)

            # Format balance message to send back to ATM
            balance_message = f"Your savings account balance: {savings_balance}\nYour checking account balance: {checking_balance}"

            # Send account balances back to the ATM
            client_socket.send(balance_message.encode())

        elif user_action == '3':  # Option 3: Exit
            client_socket.close()
            break

        else:
            client_socket.send(b'Incorrect input. Please select a valid option.')

    else:
        client_socket.send(b'unsuccess')
    # Close the connection socket
    client_socket.close()

# Close the server socket
server_socket.close()
