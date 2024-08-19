from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import uuid
import logging


logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.DEBUG,
    datefmt="%Y-%m-%d %H:%M:%S",
    filename="error.log",
)

app = FastAPI()

messages: List[str] = []
client_sessions: Dict[str, bytes] = {}

# Generate RSA key pair for the server
private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
public_key = private_key.public_key()


class SessionKey(BaseModel):
    encrypted_session_key: str


class Message(BaseModel):
    content: str
    session_id: str


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


@app.get("/public_key/")
async def get_public_key():
    return {
        "public_key": public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    }


@app.post("/set_session_key/")
async def set_session_key(session_key: SessionKey):
    try:
        session_key_bytes = base64.b64decode(session_key.encrypted_session_key)
        decrypted_session_key = private_key.decrypt(
            session_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        session_id = str(uuid.uuid4())
        client_sessions[session_id] = decrypted_session_key
        return {"status": "Session key received and set.", "session_id": session_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/send_message/")
async def send_message(message: Message):
    session_key = client_sessions.get(message.session_id)
    if session_key is None:
        raise HTTPException(status_code=403, detail="Invalid session ID.")
    try:
        encrypted_message = base64.b64decode(message.content)
        decrypted_message = decrypt_message(encrypted_message, session_key)
        messages.append(decrypted_message)
        return {"message": f"Message received: {decrypted_message}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/get_messages/")
async def get_messages(session_id: str):
    session_key = client_sessions.get(session_id)
    if session_key is None:
        raise HTTPException(status_code=403, detail="Invalid session ID.")
    try:
        encrypted_messages = [
            base64.b64encode(encrypt_message(msg, session_key)).decode("utf-8")
            for msg in messages
        ]
        return encrypted_messages
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
