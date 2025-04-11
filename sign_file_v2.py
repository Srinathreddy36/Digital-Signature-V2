from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64

def generate_keys():
    # Generate RSA Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get public key from private key
    public_key = private_key.public_key()

    return private_key, public_key

def save_public_key_as_text(public_key, filename="public_key.txt"):
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "w") as f:
        f.write(public_pem.decode())

def sign_file(file_path, private_key):
    with open(file_path, "rb") as f:
        data = f.read()

    # Sign the file using SHA-256
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Save the signature
    with open("signature.sig", "wb") as f:
        f.write(signature)

    print("✅ File signed successfully.")
    print("📁 Signature saved as: signature.sig")

def main():
    file_path = input("📄 Enter the file path to sign (e.g., agreement.pdf): ").strip()
    private_key, public_key = generate_keys()
    save_public_key_as_text(public_key)

    sign_file(file_path, private_key)

    print("\n🔑 Public key saved in text format: public_key.txt")
    print("📨 Share this file content securely with the receiver (e.g., via email/message).")
    print("🚀 Now you can upload the signed file and signature to GitHub or any cloud for access.")

if __name__ == "__main__":
    main()
