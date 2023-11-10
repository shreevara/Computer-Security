# genpasswd.py

import hashlib
import getpass
from datetime import datetime
import os

def generate_hashed_password(password):
    # Use hashlib to hash the password
    hash_object = hashlib.sha256(password.encode())
    return hash_object.hexdigest()

def check_id_exists(user_id):
    if not os.path.exists("hashpasswd"):
        return False

    with open("hashpasswd", "r") as file:
        for line in file:
            parts = line.strip().split(' ', 2)
            if len(parts) < 3:
                continue
            stored_id, _, _ = parts
            if stored_id == user_id:
                return True
    return False

def main():
    if not os.path.exists("hashpasswd"):
        open("hashpasswd", "a").close()

    while True:
        user_id = input("Enter your ID: ")
        if not user_id.islower():
            print("The ID should only contain lower-case letters")
            continue

        if check_id_exists(user_id):
            print("The ID already exists")
            choice = input("Would you like to enter another ID and Password (Y/N)? ")
            if choice.lower() != "y":
                break
            else:
                continue

        password = getpass.getpass("Enter your password: ")
        if len(password) < 8:
            print("The password should contain at least 8 characters")
            continue

        hashed_password = generate_hashed_password(password)
        creation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open("hashpasswd", "a") as file:
            file.write(f"{user_id} {hashed_password} {creation_time}\n")

        choice = input("Would you like to enter another ID and Password (Y/N)? ")
        if choice.lower() != "y":
            break

if __name__ == "__main__":
    main()
