from socket import socket, AF_INET, SOCK_STREAM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import pickle

def load_public_key():
    with open("public_key.pem", "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read(), backend=None)

def encrypt_with_public_key(public_key, data):
    ciphertext = public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def main():
    public_key = load_public_key()

    s = socket(AF_INET, SOCK_STREAM)
    s.connect(("remote.cs.binghamton.edu", 6599))

    # Step S3
    sym_key = "sample_symmetric_key"  # Replace with actual symmetric key generation
    sym_key_encrypted = encrypt_with_public_key(public_key, sym_key)

    user_id = input("Enter your ID: ")
    password = input("Enter your password: ")
    id_password = f"{user_id} {password}"
    id_password_encrypted = encrypt_with_public_key(public_key, id_password)

    data_to_send = pickle.dumps((sym_key_encrypted, id_password_encrypted))
    s.sendall(data_to_send)

    server_response = s.recv(1024)
    response_message = server_response.decode('utf-8')
    print(response_message)

    while "incorrect" in response_message:
        # Prompt user to re-enter ID and password
        user_id = input("Enter your ID: ")
        password = input("Enter your password: ")
        id_password = f"{user_id} {password}"
        id_password_encrypted = encrypt_with_public_key(public_key, id_password)

        data_to_send = pickle.dumps((sym_key_encrypted, id_password_encrypted))
        s.sendall(data_to_send)

        server_response = s.recv(1024)
        response_message = server_response.decode('utf-8')
        print(response_message)

    if response_message == "ID and password are correct":
        while True:
            print("Please select one of the following actions:")
            print("1. Transfer money")
            print("2. Check account balance")
            print("3. Exit")

            choice = input("Enter your choice (1, 2, or 3): ")

            if choice == "1":
                s.sendall(b"1")
                while True:
                    print("Select an account to transfer from:")
                    print("1. Savings")
                    print("2. Checking")

                    account_choice = input("Enter your choice (1 or 2): ")

                    if account_choice in ["1", "2"]:
                        s.sendall(account_choice.encode('utf-8'))

                        recipient_id = input("Enter recipient's ID: ")
                        s.sendall(recipient_id.encode('utf-8'))

                        transfer_amount = float(input("Enter the transfer amount: "))
                        s.sendall(str(transfer_amount).encode('utf-8'))

                        # Receive and print the response from the server
                        server_response = s.recv(1024)
                        print(server_response.decode('utf-8'))
                        break

                    else:
                        print("Incorrect input. Please try again.")

            elif choice == "2":
                s.sendall(b"2")  

                balances_response = s.recv(1024).decode('utf-8')

                # Parse and print the balances
                user_balances = balances_response.split('\n')
                for user_balance in user_balances:
                    user_data = user_balance.split()
                    if len(user_data) == 3:
                        user_id, savings_balance, checking_balance = user_data
                        print(f"Your savings account balance: {savings_balance}")
                        print(f"Your checking account balance: {checking_balance} \n")
                    else:
                        print("Invalid balance format received from the server.")

            elif choice == "3":
                s.sendall(b"3")  # Step S8
                break

            else:
                print("Incorrect input. Please try again.")




if __name__ == "__main__":
    main()
