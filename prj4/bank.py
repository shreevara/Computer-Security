from socket import socket, AF_INET, SOCK_STREAM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import pickle

def load_private_key():
    with open("private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=None
        )

def decrypt_with_private_key(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def validate_credentials(user_id, password):
    # Load user credentials from the "password" file
    with open("password", "r") as password_file:
        for line in password_file:
            stored_id, stored_password = line.strip().split()
            if user_id == stored_id and password == stored_password:
                return True
    return False

def get_user_balance(user_id):
    # Load user balances from the "balance" file
    with open("balance", "r") as balance_file:
        for line in balance_file:
            stored_id, savings_balance, checking_balance = line.strip().split()
            if user_id == stored_id:
                return f"{user_id} {savings_balance} {checking_balance}"
    return f"{user_id} 0 0"  # Default to 0 balance if user not found


def main():
    private_key = load_private_key()

    s = socket(AF_INET, SOCK_STREAM)
    s.bind(("remote.cs.binghamton.edu", 6599))
    s.listen(5)

    print("Bank Server listening on port 12345...")

    while True:
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)

            # Step S2
            client_data = conn.recv(1024)
            sym_key_encrypted, id_password_encrypted = pickle.loads(client_data)

            # Step S4
            sym_key = decrypt_with_private_key(private_key, sym_key_encrypted)
            id_password = decrypt_with_private_key(private_key, id_password_encrypted)
            user_id, password = id_password.split()

            while not validate_credentials(user_id, password):
                conn.sendall(b"ID or password is incorrect")

                # Receiving the re-entered credentials
                client_data = conn.recv(1024)
                sym_key_encrypted, id_password_encrypted = pickle.loads(client_data)
                sym_key = decrypt_with_private_key(private_key, sym_key_encrypted)
                id_password = decrypt_with_private_key(private_key, id_password_encrypted)
                user_id, password = id_password.split()

            # Step S4 validation
            if validate_credentials(user_id, password):
                conn.sendall(b"ID and password are correct")
                # Send the balance information for the authenticated user
                user_balance = get_user_balance(user_id)
                conn.sendall(user_balance.encode('utf-8'))
                # Receive the client's choice
                client_choice = conn.recv(1024).decode('utf-8')

                if client_choice == "1":  # Client selected option 1 (Transfer money)
                    # Implement steps S6 - S7 for money transfer
                    transfer_data = conn.recv(1024).decode('utf-8')  # Receive transfer data from the client
                    # Process the transfer data and update balances accordingly
                    # Send the appropriate response to the client

                elif client_choice == "2":  # Client selected option 2 (Check account balance)
                    # Send the balances of both the savings and checking accounts back to the client
                    user_balance = get_user_balance(user_id)
                    conn.sendall(user_balance.encode('utf-8'))

                elif client_choice == "3":  # Client selected option 3 (Exit)
                    break
            else:
                conn.sendall(b"ID or password is incorrect")

           

if __name__ == "__main__":
    main()
