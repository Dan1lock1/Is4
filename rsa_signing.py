import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

def create_signature(message):
    message_bytes = message.encode()
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def send_data(message, signature, public_key):
    data = {
        'message': message,
        'signature': signature,
        'public_key': public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    }
    serialized_data = pickle.dumps(data)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))
        s.sendall(serialized_data)

def main():
    message = input("Enter the message: ")
    signature = create_signature(message)
    send_data(message, signature, public_key)

if __name__ == "__main__":
    main()
