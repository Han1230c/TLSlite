# Client-Server Secure Communication System

## Overview

This project implements a secure communication system between a **Client** and a **Server** using **Diffie-Hellman key exchange** and **AES encryption**. The communication process includes mutual authentication and message integrity verification to ensure the confidentiality and authenticity of the messages exchanged between the client and server.

## Features

- **Diffie-Hellman Key Exchange**: Securely generates shared secret keys for encrypting messages.
- **AES Encryption**: Encrypts and decrypts messages using AES in CBC mode with HMAC for integrity verification.
- **Digital Signatures**: RSA-based signatures are used to sign Diffie-Hellman public keys during the handshake process.
- **Mutual Authentication**: Both the client and server verify certificates signed by a trusted Certificate Authority (CA).
- **Message Integrity Verification**: HMAC is used to ensure the integrity of the messages exchanged.

## Project Structure

- **Client.java**: Implements client-side logic, including handshake, key exchange, message encryption, and decryption.
- **Server.java**: Implements server-side logic, including handshake, key exchange, message encryption, and decryption.
- **SecurityUtils.java**: Provides helper functions for cryptographic operations like key generation, encryption, decryption, HMAC calculation, certificate verification, and digital signature operations.
- **Message.java**: Encapsulates the encrypted message and its HMAC for integrity verification.

## Dependencies

- **Java Cryptography Extension (JCE)**: Utilizes built-in cryptography libraries in Java (`javax.crypto`, `java.security`).
- **X.509 Certificates**: Uses PEM-encoded X.509 certificates for client and server authentication.

## How to Run

1. **Set Up Certificates**:
    - Place the CA-signed client and server certificates in the `resources` directory.
    - Place the private keys for the client and server in the same directory.

2. **Run the Server**:
    - Compile and run the `Server.java` class to start the server.
    - The server listens on port `8080` for incoming client connections.

   ```bash
   javac Server.java
   java Server
