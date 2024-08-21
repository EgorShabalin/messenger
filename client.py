import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import logging


logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.DEBUG,
    datefmt="%Y-%m-%d %H:%M:%S",
    filename="error.log",
)

server_url = input("Enter server URL: ")

username = input("Enter your name: ")


def generate_session_key():
    session_key = os.urandom(32)  # 256-bit key for AES
    if session_key:
        logging.info("Session key created!")
    return session_key


def encrypt_message(message: str, session_key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(session_key), modes.CFB(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    result = iv + ciphertext
    if result:
        logging.info("Message encrypted!")
    return result


def decrypt_message(encrypted_message: bytes, session_key: bytes) -> str:
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(
        algorithms.AES(session_key), modes.CFB(iv), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    result = (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    if result:
        logging.info("Message decrypted!")
    return result


def get_public_key():
    try:
        response = requests.get(f"{server_url}/public_key/")
        response.raise_for_status()
        if response:
            logging.info("Got public key!")
        return response.json()["public_key"]
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        print(f"Request failed: {e}")
        return ""


def set_session_key(session_key: bytes):
    try:
        encrypted_session_key = base64.b64encode(
            public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        ).decode("utf-8")
        response = requests.post(
            f"{server_url}/set_session_key/",
            json={"encrypted_session_key": encrypted_session_key},
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        print(f"Request failed: {e}")
        return {}


def send_message(message: str, session_id: str):
    encrypted_message = encrypt_message(message, session_key)
    encoded_message = base64.b64encode(encrypted_message).decode("utf-8")
    try:
        response = requests.post(
            f"{server_url}/send_message/",
            json={"content": encoded_message, "session_id": session_id},
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        print(f"Request failed: {e}")
        return {}


def get_messages(session_id: str):
    try:
        logging.info("Sending request!")
        response = requests.get(
            f"{server_url}/get_messages/", params={"session_id": session_id}
        )
        response.raise_for_status()
        encoded_messages = response.json()
        result = [
            decrypt_message(base64.b64decode(msg), session_key)
            for msg in encoded_messages
        ]
        if result:
            logging.info("Got messages!")
        else:
            logging.info("Did Not get messages.")
        return result
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        print(f"Request failed: {e}")
        return []


def start_client():
    public_key_pem = get_public_key()
    if not public_key_pem:
        logging.error("Failed to get public key.")
        print("Failed to get public key.")
        return

    global public_key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(), backend=default_backend()
    )

    global session_key
    session_key = generate_session_key()
    response = set_session_key(session_key)
    if not response:
        logging.error("Failed to set session key.")
        print("Failed to set session key.")
        return

    session_id = response.get("session_id")
    if not session_id:
        logging.error("Failed to get session ID.")
        print("Failed to get session ID.")
        return

    logging.info(f"Session established with ID: {session_id}")
    print(f"Session established with ID: {session_id}")

    def user_send_message(action):
        message = username + ":" + " " + action
        response = send_message(message, session_id)
        if response:
            logging.info("Message Sent!")
            print("Message Sent!")

    def user_receive_messages():
        messages = get_messages(session_id)
        if messages:
            logging.info("Messages received by client.")
            print("\nMessages:")
        else:
            logging.info("NO messages received by client.")
            print("NO messages received.")
        for msg in messages:
            print(f"    {msg}")

    while True:

        action = input(
            "\nEnter your message and press 'Enter' to send message or leave blanc and press 'Enter' to retrieve messages:\n "
        )

        if len(action) > 0:
            user_send_message(action)
            user_receive_messages()

        elif len(action) == 0:
            user_receive_messages()

        elif action.lower() == "quit":
            logging.info("Exiting...")
            print("Exiting...")
            break

        else:
            print("Unknown command. Please try again.")


if __name__ == "__main__":
    start_client()
