import sys
import os
import base64
import sqlite3
import threading
import time
import tempfile
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from user import User
from database import Database

"""
'import sys': Used to access the command line arguments in the 'main'
'import base64': Used to encode and decode encrypted payloads in the 'send_message' and the 'receive_message'
'import sqlite3': Used to interact with the SQLit databases
'import threading': Used to create a separate thread for polling messages in the 'main' function.
'import time': Used in the 'poll_messages' to add a delay between polling for new messages.
'from Crypto.Cipher import AES, PKCS1_OEAP': These are the encryption ciphers used for AES and RSA encryption.
'from Crypto.Random import get_random_bytes': Used to generate random bytes for AES key, IV, and RSA key pairs.
'from Crypto.PublicKey import RSA': Used for working with RSA public and private keys.
'from Crypto.Util.Padding import pad,unpad': These functions are used to pad and unpad plaintext before and after AES encryption and decryption.
'from user import User': Used to create and work with User objects throughout the code.
'from database import Database': Used to create a Database object in the 'main' for managing user registration, login, and message storage.
"""


def generate_rsa_key_pair(key_size=2048):
    """
    Generate an RSA key pair with the given key size.

    :param key_size: The size of the RSA keys to be generated (default: 2048)
    :return:
        tuple: A tuple containing the private key and public key objects.
    """
    # Generate a new private key object
    private_key = RSA.generate(key_size)
    # Extract the public key from the private key
    public_key = private_key.publickey()
    # Return the private and public keys as a tuple
    return private_key, public_key


def rsa_encrypt(plaintext, public_key):
    """
    Encrypts the plaintext using thr given public key with RSA and PKCS1_OAEP padding.

    :param plaintext: The plaintext to be encrypted.
    :param public_key: The public key to be used for encryption.
    :return:
        bytes: The encrypted ciphertext.
    """
    # Create a new PKCS1_OAEP cipher object with
    cipher = PKCS1_OAEP.new(public_key)
    # Encrypt the plaintext using the ciphertext
    ciphertext = cipher.encrypt(plaintext)
    # Return thr encrypted ciphertext
    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    """
    Decrypts the ciphertext using the given private key with RSA and PKCS1_OAEP padding.

    :param ciphertext: The ciphertext to be decrypted.
    :param private_key: The private key to be used for decryption.
    :return:
        bytes: The decrypted plaintext.
    """
    # Create a new PKCS1_OAEP cipher object with the given private key
    cipher = PKCS1_OAEP.new(private_key)
    # Decrypt the ciphertext using thr cipher object
    plaintext = cipher.decrypt(ciphertext)
    # Return the decrypted plaintext
    return plaintext


def aes_encrypt(plaintext, key, iv):
    """
    Encrypts the plaintext using the given key and IV with AES in CBC mode and PKCS7 padding.

    :param plaintext: The plaintext to be encrypted.
    :param key: The symmetric key to be used for encryption.
    :param iv: The initialization vector to be used for encryption.
    :return:
        The encrypted ciphertext.
    """
    # Create a new AES cipher object with the given key, initialization vector (IV), and mode of operation (CBC)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Encrypt the plaintext using the cipher object and PKCS7 padding
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Return the encrypted ciphertext
    return ciphertext


def aes_decrypt(ciphertext, key, iv):
    """
    Decrypts the ciphertext using the given key and IV with AES and CBC mode and PKCS7 padding.

    :param ciphertext: The ciphertext to be decrypted.
    :param key: The symmetric key to be used for decryption.
    :param iv: The initialization vector to be used for decryption.
    :return:
        bytes: The decrypted plaintext.
    """
    # Create a new AES cipher object with the new given key, initialization vector (IV), and mode of operation (CBC)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the ciphertext using the cipher object and PKCS7 padding, then remove padding
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    # Return the decrypted plaintext
    return plaintext


def send_message(message, recipient_public_key):
    """
    Encrypts a message using the recipient's public key and generates an encrypted payload.

    :param message: The message to be encrypted.
    :param recipient_public_key: The recipient's public key to be used for encryption.
    :return:
        str: The encrypted payload containing the encrypted AES key, IV, and message.
    """
    # Generate random AES key and IV
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)

    # Encrypt the message using AES
    encrypted_message = aes_encrypt(message.encode(), aes_key, iv)

    # Encrypt the AES key and IV using the recipient's public key
    encrypted_aes_key = rsa_encrypt(aes_key, recipient_public_key)
    encrypted_iv = rsa_encrypt(iv, recipient_public_key)

    # Combine the encrypted AES key, IV, and message into a single string
    encrypted_payload = base64.b64encode(encrypted_aes_key + encrypted_iv + encrypted_message).decode()
    return encrypted_payload


def receive_message(encrypted_payload, recipient_private_key):
    """
    This function takes an encrypted payload and the recipient's private key,
    then decrypts the payload to reveal the original message.

    :param encrypted_payload: A string representing the encrypted payload,
    which contains the encrypted AES key, IV, and message.
    :param recipient_private_key: An RSA private key object of the recipient.
    :return: The decrypted message as a string.
    """
    decoded_payload = base64.b64decode(encrypted_payload.encode())

    # Extract the encrypted AES key, IV, and message
    encrypted_aes_key, encrypted_iv, encrypted_message = (
        decoded_payload[:256], decoded_payload[256:512], decoded_payload[512:])

    # Decrypt the AES key and IV using the recipient's private key
    aes_key = rsa_decrypt(encrypted_aes_key, recipient_private_key)
    iv = rsa_decrypt(encrypted_iv, recipient_private_key)

    # Decrypt the message using the decrypted AES key and IV
    message = aes_decrypt(encrypted_message, aes_key, iv).decode()
    return message


def poll_messages(db, user):
    """
    This function polls the database for new messages addressed to the user.
    If new messages are found, they are decrypted and displayed.

    :param db: A Database object to interact with the database.
    :param user: A User object representing the logged-in user.
    """
    previous_messages = set()

    while True:
        # Get all messages for the user from the database
        messages = db.get_messages_for_user(user.username)
        # Filter out messages that have already been displayed
        new_messages = set(messages) - previous_messages

        # Decrypt and display new messages
        for sender, recipient, encrypted_payload in new_messages:
            message_received = receive_message(encrypted_payload, user.private_key)
            print(f"\n{sender}: {message_received}")

        # Update the set of previously displayed messages
        previous_messages = set(messages)
        time.sleep(1)

def encrypt_file(input_file_path, output_file_path, public_key):
    with open(input_file_path, "rb") as f:
        file_data = f.read()

    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(file_data)

    with open(output_file_path, "wb") as f:
        f.write(encrypted_data)

def decrypt_file(input_file_path, output_file_path, private_key):
    with open(input_file_path, "rb") as f:
        encrypted_data = f.read()

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)

    with open(output_file_path, "wb") as f:
        f.write(decrypted_data)

def send_file(input_file_path, recipient_public_key):
    encrypted_file_path = os.path.join(tempfile.gettempdir(), "temp_encrypted_file.bin")
    encrypt_file(input_file_path, encrypted_file_path, recipient_public_key)

    with open(encrypted_file_path, "rb") as f:
        encrypted_payload = f.read()

    os.remove(encrypted_file_path)
    return encrypted_payload

def receive_file(encrypted_payload, output_file_path, recipient_private_key):
    encrypted_file_path = os.path.join(tempfile.gettempdir(), "temp_encrypted_file.bin")

    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_payload)

    decrypt_file(encrypted_file_path, output_file_path, recipient_private_key)
    os.remove(encrypted_file_path)


# def main():
#     """
#     The main function handles the user registration and login, as well as chat setup and interaction.
#
#     It takes command line arguments to determine whether to register or login a user.
#     After successful registration or login, it prompts the user for the recipient's username
#     and starts a chat session.
#     """
#     # Check if the user provided a valid command-line argument
#     if len(sys.argv) < 2:
#         print("Usage: python secure_messaging.py [register|login]")
#         sys.exit(1)
#
#     # Get the user's command-line argument
#     mode = sys.argv[1].lower()
#     # Create a database object to interact with SQLite database
#     db = Database()
#
#     # If the user want to register a new account
#     if mode == "register":
#         # Prompt the user to enter their username, password, and generate RSA key pair
#         username = input("Enter your username: ")
#         password = input("Enter your password: ")
#         private_key, public_key = generate_rsa_key_pair()
#         user = User(username, password, private_key, public_key)
#
#         # Attempt to add the new user to the database
#         try:
#             db.add_user(user)
#             print("User registered successfully!")
#         except sqlite3.IntegrityError:
#             print("Error: The username is already taken.")
#
#     # If the user wants to log in to an existing account
#     elif mode == "login":
#
#         # Prompt the user to enter their username and password
#         username = input("Enter your username: ")
#         password = input("Enter your password: ")
#         # Retrieve the user's information from the database
#         user = db.get_user(username, password)
#         # If the user was found in the database
#         if user:
#             print("Login successful!")
#             print("Your private key:")
#             print(user.private_key.export_key().decode())
#             print("\nYour public key:")
#             print(user.public_key.export_key().decode())
#         else:
#             print("Login failed. Check your username and password.")
#
#     # If the user did not provide a valid command-line argument
#     else:
#         print("Invalid mode. Use 'register' or 'login'.")
#         sys.exit(1)
#
#     # Prompt the user to enter the username of the recipient they want to chat with
#     print("\nYou are now logged in. Enter the recipient's username to start a chat:")
#     recipient_username = input("Recipient: ")
#
#     # Retrieve the recipient's information from the database
#     recipient = db.get_user(recipient_username)
#
#     # If the recipient was not found in the database exit
#     if not recipient:
#         print("Recipient not found.")
#         sys.exit(1)
#
#     # Notify the user that they can start chatting with the recipient
#     print("\nYou can now chat with", recipient_username)
#     print("To exit the chat, type 'exit'\n")
#
#     # Start a thread for polling new messages
#     message_poll_thread = threading.Thread(target=poll_messages, args=(db, user))
#     message_poll_thread.daemon = True
#     message_poll_thread.start()
#
#     # Continuously prompt the user to enter messages to send to the recipient
#     while True:
#         message = input()
#
#         # If the user wants to exit the chat
#         if message.lower() == "exit":
#             break
#
#         # Encrypt the messages using the recipient's public key and add it to the database
#         encrypted_payload = send_message(message, recipient.public_key)
#         db.add_message(user.username, recipient.username, encrypted_payload)
def main():
    """
    The main function handles the user registration and login, as well as chat setup and interaction.

    It takes command line arguments to determine whether to register or login a user.
    After successful registration or login, it prompts the user for the recipient's username
    and starts a chat session.
    """
    print("Welcome to Secure Messaging App!")
    print("=================================")

    while True:
        mode = input("Enter 'register' to create an account or 'login' to sign in: ").lower()

        if mode in ['register', 'login']:
            break
        else:
            print("Invalid input. Please enter 'register' or 'login'.")

    db = Database()

    if mode == "register":
        while True:
            username = input("Enter your desired username: ")
            password = input("Enter a strong password: ")
            private_key, public_key = generate_rsa_key_pair()
            user = User(username, password, private_key, public_key)

            try:
                db.add_user(user)
                print("User registered successfully!")
                break
            except sqlite3.IntegrityError:
                print("Error: The username is already taken. Please try again.")

    elif mode == "login":
        while True:
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            user = db.get_user(username, password)

            if user:
                print("Login successful!")
                print("\nYour private key:")
                print(user.private_key.export_key().decode())
                print("\nYour public key:")
                print(user.public_key.export_key().decode())
                break
            else:
                print("Login failed. Check your username and password and try again.")

    while True:
        recipient_username = input("\nEnter the username of the person you want to chat with: ")
        recipient_public_key = db.get_public_key(recipient_username)

        if recipient_public_key:
            print(f"\nYou can now chat with {recipient_username}. Type 'exit' to end the chat session.\n")
            threading.Thread(target=poll_messages, args=(db, user), daemon=True).start()

            while True:
                message = input()
                if message.lower() == "exit":
                    break

                encrypted_payload = send_message(message, recipient_public_key)
                db.add_message(user.username, recipient_username, encrypted_payload)
                print("Message sent!")
        else:
            print("Error: The specified recipient does not exist. Please try again.")


if __name__ == "__main__":
    main()
