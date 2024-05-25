import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def verify_signature(message, signature, public_key_bytes):
    public_key = serialization.load_pem_public_key(public_key_bytes)
    message_bytes = message.encode()
    
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def receive_data():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
        s.listen()
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            if data:
                received_data = pickle.loads(data)
                message = received_data['message']
                signature = received_data['signature']
                public_key_bytes = received_data['public_key']
                
                is_valid = verify_signature(message, signature, public_key_bytes)
                if is_valid:
                    print("The signature is valid.")
                    print(f"Received message: {message}")
                else:
                    print("The signature is invalid.")

if __name__ == "__main__":
    receive_data()
