from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import pickle  # For serialization

# Load the bank server's public key
with open('bank_public.pem', 'rb') as public_file:
    bank_public_key = RSA.import_key(public_file.read())

# Establish connection to the bank server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('remote00.cs.binghamton.edu', 12345))  # Replace with actual server details

symmetric_key = get_random_bytes(16)  # 128-bit key for AES

    # Encrypt the symmetric key using the bank's public key

while True:
# Step 2: Prompt user for ID and password
    user_id = input("Enter your ID: ")
    password = input("Enter your password: ")

    # Step 3: Generate a symmetric key K
    
    cipher_rsa = PKCS1_OAEP.new(bank_public_key)
    encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)
    # Encrypt ID and password using the symmetric key
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    ciphertext_id_password, tag_id_password = cipher_aes.encrypt_and_digest(pickle.dumps((user_id, password)))
    print(ciphertext_id_password)
    # Send the encrypted symmetric key, encrypted ID/password, and action to the server
    print(cipher_aes.nonce)
    client_socket.send(encrypted_symmetric_key)
    client_socket.send(cipher_aes.nonce)
    client_socket.send(tag_id_password)
    client_socket.send(ciphertext_id_password)

    # Step 4: Receive and process server response
    response_symmetric_key = client_socket.recv(4096)
    response_nonce = client_socket.recv(16)
    response_tag = client_socket.recv(16)
    response_ciphertext = client_socket.recv(4096)

    # Decrypt server's response using the received symmetric key
    cipher_aes_response = AES.new(symmetric_key, AES.MODE_EAX, nonce=response_nonce)
    decrypted_response = cipher_aes_response.decrypt_and_verify(response_ciphertext, response_tag)

    # Display server's response to the user
    if decrypted_response.decode() == 'success':
        print("ID and password are correct")
        break
    else:
        print("ID or password is incorrect")

# Handle menu options (steps 5 to 9) based on user's choice...
while True:
    # Step 5: Display the main menu
    print("Please select one of the following actions (enter 1, 2, or 3):")
    print("1. Transfer money")
    print("2. Check account balance")
    print("3. Exit")

    user_choice = input("Enter your choice: ")

    if user_choice == '1':  # Option 1: Transfer money
        print("Please select an account (enter 1 or 2):")
        print("1. Savings")
        print("2. Checking")
        while True:
            user_c = input("Enter your choice: ")
            if not(user_c == 'Savings' or user_c == 'Checking'):
                print("incorrect input")
            else:
                break
        
        # Implement transfer money logic
        recipient_id = input("Enter recipient's ID: ")
        transfer_amount = float(input("Enter the amount to transfer: "))

        # Construct data for transfer
        transfer_data = {
            'action': '1',
            'account': user_c,
            'recipient_id': recipient_id,
            'transfer_amount': transfer_amount
            # Add any other necessary information for the transfer
        }

        # Encrypt the transfer data using the symmetric key
        ciphertext_transfer, tag_transfer = cipher_aes.encrypt_and_digest(pickle.dumps(transfer_data))

        # Send encrypted transfer data to the server
        client_socket.send(ciphertext_transfer)
        client_socket.send(tag_transfer)

        # Receive server response for transfer
        response_transfer = client_socket.recv(4096)

        # Decrypt the transfer response using the symmetric key
        cipher_aes_transfer = AES.new(symmetric_key, AES.MODE_EAX)
        decrypted_transfer = cipher_aes_transfer.decrypt(response_transfer)

        # Display the transfer response to the user
        print(decrypted_transfer.decode())

    elif user_choice == '2':  # Option 2: Check account balance
        # Send request to server for account balance
        transfer_data = {
            'action': '1',
            'account': 'None',
            'recipient_id': 'None',
            'transfer_amount': 'None'
            # Add any other necessary information for the transfer
        }
        ciphertext_transfer, tag_transfer = cipher_aes.encrypt_and_digest(pickle.dumps(transfer_data))

        # Send encrypted transfer data to the server
        client_socket.send(ciphertext_transfer)
        client_socket.send(tag_transfer) # Send option 2 to server

        # Receive balances from the server
        response_balance = client_socket.recv(4096)

        # Decrypt balance data using the symmetric key
        cipher_aes_balance = AES.new(symmetric_key, AES.MODE_EAX)
        decrypted_balance = cipher_aes_balance.decrypt(response_balance)

        # Display account balances to the user
        print(decrypted_balance.decode())

    elif user_choice == '3':  # Option 3: Exit
        # Send exit signal to server
        client_socket.send(b'3')  # Send option 3 to server

        # Close the connection sockets and exit the loop
        client_socket.close()
        break

    else:
        print("Incorrect input. Please enter a valid option.")

# End of menu option handling
client_socket.close()
