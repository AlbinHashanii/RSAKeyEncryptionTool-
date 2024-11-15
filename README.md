
# RSA Key Encryption

This project demonstrates a secure system for managing digital prescriptions using cryptography. It ensures that prescriptions are both authentic and confidential, providing a robust mechanism for secure communication between a doctor and a pharmacy.

## Project Information

- Institution: University of Pristina "Hasan Prishtina"
- Program: Master's Degree, Computer and Software Engineering
- Professor: Dr. Sc. Mërgim H. HOTI

## Authors

- [Albin Hashani](https://github.com/AlbinHashanii)
- [Arjana Tërnava](https://github.com/ArjanaaTernava)
- [Erza Osmani](https://github.com/erzaosmani)

## Project Overview and Results

- Generation and display of RSA key pairs for the doctor and pharmacy to achieve secure encryption and decryption. 

  ```bash
  doctor_private_key, doctor_public_key =   generate_rsa_keypair()
  pharmacy_private_key, pharmacy_public_key = generate_rsa_keypair()
  ```  
- After generating the private and public keys, the results are printed in the PEM format: 
  ```bash
  Doctor's Private Key:
  -----BEGIN PRIVATE KEY-----
  MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDDq/1RZgmxtP3p
   ``` 
    ```bash
  Doctor's Public Key:
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw6v9UWYJsbT96Vx6hZnV
    ```
     ```bash
  Pharmacy's Private Key:
  -----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6h/G+NQKzbuVj
    ```
     ```bash
     Pharmacy's Public Key:
     -----BEGIN PUBLIC KEY-----
     MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuofxvjUCs27lY/1l2HeF
    ```

- Note: For security reasons, the results of the keys are not displayed fully, just the beginning part of the key.

- User Input: The project allows the user to input a prescription that needs to be securely transmitted.

- Encryption and Signing: The prescription is signed with the doctor’s private key to ensure authenticity and encrypted with the pharmacy’s public key for secure transmission.

  ```bash
     Enter the prescription text: Take antibiotics every 12 hours.
     Prescription encrypted and signed by the doctor. 
    ```
- File Output (Encrypted Prescription): The encrypted prescription is saved to a file named `encrypted_prescription.bin` for secure sharing.
    ```bash
       Encrypted prescription saved to 'encrypted_prescription.bin'.
       Prescription verified. The prescription is authentic.
    ```
- Decryption and Verification: The pharmacy decrypts the prescription using its private key and verifies its authenticity with the doctor’s public key.  

- File Output (Decrypted Prescription): The verified prescription is saved to a file named `decrypted_prescription.txt` for further use.

  ```bash
     Decrypted Prescription: Take antibiotics every 12 hours.
     Decrypted prescription saved to 'decrypted_prescription.txt'.
    ```

### License

[Apache-2.0](http://www.apache.org/licenses/)










