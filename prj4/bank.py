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
    lines = balance_file.readlines()
    user_balances = []
    for line in lines:
      stored_id, savings_balance, checking_balance = line.strip().split()
      if stored_id == user_id:
        user_balances.append(f"{stored_id} {savings_balance} {checking_balance}")
    return "\n".join(user_balances)

  return f"{user_id} 0 0"  # Default to 0 balance if user not found


def perform_money_transfer(user_id, sender_account, recipient_id, transfer_amount):
    # Check if the recipient's ID exists
    recipient_exists = False
    with open("password", "r") as password_file:
        for line in password_file:
            stored_id, _ = line.strip().split()
            if recipient_id == stored_id:
                recipient_exists = True
                break

    if not recipient_exists:
        return "The recipient's ID does not exist\n"

    # Load user balances from the "balance" file
    with open("balance", "r") as balance_file:
        lines = balance_file.readlines()

    for i, line in enumerate(lines):
        stored_id, savings_balance, checking_balance = line.strip().split()
        if user_id == stored_id:
            if sender_account == "1" and float(savings_balance) >= transfer_amount:
                # Update sender's savings balance
                lines[i] = f"{stored_id} {float(savings_balance) - transfer_amount} {checking_balance}\n"
            elif sender_account == "2" and float(checking_balance) >= transfer_amount:
                # Update sender's checking balance
                lines[i] = f"{stored_id} {savings_balance} {float(checking_balance) - transfer_amount}\n"
            else:
                return "Your account does not have enough funds\n"

        elif recipient_id == stored_id:
            # Update recipient's balances
            if sender_account == "1":
                lines[i] = f"{stored_id} {float(savings_balance) + transfer_amount} {checking_balance}\n"
            elif sender_account == "2":
                lines[i] = f"{stored_id} {savings_balance} {float(checking_balance) + transfer_amount}\n"

    # Write updated balances back to the "balance" file
    with open("balance", "w") as updated_balance_file:
        updated_balance_file.writelines(lines)

    return "Your transaction is successful\n"


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

                while True:

                    # Receive the client's choice
                    client_choice = conn.recv(1024).decode('utf-8')
                    #print(f"client_choice: {client_choice}")

                    try:

                        if client_choice == "1":  # Client selected option 1 (Transfer money)
                            # Implement steps S6 - S7 for money transfer
                            account_choice = conn.recv(1024).decode('utf-8')
                            recipient_id = conn.recv(1024).decode('utf-8')
                            transfer_amount = conn.recv(1024).decode('utf-8')
                            transfer_amount = float(transfer_amount)
                            

                            response = perform_money_transfer(user_id, account_choice, recipient_id, transfer_amount)
                            conn.sendall(response.encode('utf-8'))

                        elif client_choice == "2":  
                            # Send the balances of both the savings and checking accounts back to the client
                            user_balance = get_user_balance(user_id)
                            conn.sendall(user_balance.encode('utf-8'))

                        elif client_choice == "3":  
                            break

                    except BrokenPipeError:
                        print("Client disconnected unexpectedly.")


            else:
                conn.sendall(b"ID or password is incorrect")

           

if __name__ == "__main__":
    main()
