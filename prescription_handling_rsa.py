from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

#RSA keys for the doctor and the pharmacy
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


doctor_private_key, doctor_public_key = generate_rsa_keypair()
pharmacy_private_key, pharmacy_public_key = generate_rsa_keypair()

# Display the private and public keys in PEM format
def display_keys():
    print("\nDoctor's Private Key:")
    print(doctor_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())

    print("\nDoctor's Public Key:")
    print(doctor_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    print("\nPharmacy's Private Key:")
    print(pharmacy_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())

    print("\nPharmacy's Public Key:")
    print(pharmacy_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())


display_keys()
