from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes


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

#Doctor writes and signs the prescription, then encrypts it for the pharmacy
def create_and_encrypt_prescription(prescription, doctor_private_key, pharmacy_public_key):
    signature = doctor_private_key.sign(
        prescription.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    encrypted_prescription = pharmacy_public_key.encrypt(
        prescription.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_prescription, signature

#Input
prescription_text = input("\nEnter the prescription text: ")

display_keys()

encrypted_prescription, signature = create_and_encrypt_prescription(
    prescription_text, doctor_private_key, pharmacy_public_key
)

with open("encrypted_prescription.bin", "wb") as enc_file:
    enc_file.write(encrypted_prescription)
print("\nPrescription encrypted and signed by the doctor.")
print("Encrypted prescription saved to 'encrypted_prescription.bin'.")



