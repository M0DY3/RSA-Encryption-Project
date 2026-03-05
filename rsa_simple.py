# rsa_project.py
# RSA Encryption/Decryption Project
# Author: Mody
# Description: Generate 2048-bit RSA key pair, encrypt and decrypt a message

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    """Generate private and public keys and save them to files"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("✅ Keys generated and saved to files.")
    return private_key, public_key

def encrypt_message(public_key, message: str):
    """Encrypt the message using the public key"""
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(private_key, encrypted):
    """Decrypt the message using the private key"""
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def main():
    message = "Security starts with encryption"
    
    # Generate keys
    private_key, public_key = generate_keys()
    
    # Encrypt the message
    encrypted = encrypt_message(public_key, message)
    print("\n🔒 Encrypted message:")
    print(encrypted)

    # Decrypt the message
    decrypted = decrypt_message(private_key, encrypted)
    print("\n🔓 Decrypted message:")
    print(decrypted)

if __name__ == "__main__":
    main()
