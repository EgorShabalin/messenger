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

server_url = "https://c99f30b83cb257357f151d48f7125448.serveo.net:443"


def generate_session_key():
    return os.urandom(32)  # 256-bit key for AES


def encrypt_message(message: str, session_key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(session_key), modes.CFB(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(encrypted_message: bytes, session_key: bytes) -> str:
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(
        algorithms.AES(session_key), modes.CFB(iv), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()


def get_public_key():
    try:
        response = requests.get(f"{server_url}/public_key/")
        response.raise_for_status()
        return response.json()["public_key"]
    except requests.RequestException as e:
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
        print(f"Request failed: {e}")
        return {}


def get_messages(session_id: str):
    try:
        response = requests.get(
            f"{server_url}/get_messages/", params={"session_id": session_id}
        )
        response.raise_for_status()
        encoded_messages = response.json()
        return [
            decrypt_message(base64.b64decode(msg), session_key)
            for msg in encoded_messages
        ]
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return []


def start_client():
    public_key_pem = get_public_key()
    if not public_key_pem:
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
        print("Failed to set session key.")
        return

    session_id = response.get("session_id")
    if not session_id:
        print("Failed to get session ID.")
        return

    print(f"Session established with ID: {session_id}")

    while True:
        action = input(
            "\nEnter 'send' to send a message or 'get' to retrieve messages (or 'quit' to exit): "
        )

        if action.lower() == "send":
            message = input("Enter your message: ")
            response = send_message(message, session_id)
            if response:
                print("Message Sent!")

        elif action.lower() == "get":
            messages = get_messages(session_id)
            print("Messages:")
            for msg in messages:
                print(f"- {msg}")

        elif action.lower() == "quit":
            print("Exiting...")
            break

        else:
            print("Unknown command. Please try again.")


if __name__ == "__main__":
    start_client()
