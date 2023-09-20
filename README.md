# Toy Stream Cipher Implementation

This repository contains the code for a toy stream cipher implementation based on a Pseudo Random Number Generator (PRNG) using the ChaCha20 algorithm. The project consists of two main components: Alice and Bob, which simulate secure communication.

## Overview

In this project, Alice and Bob exchange encrypted messages while ensuring data integrity and security. The following steps are performed by Alice and Bob:

### Alice's Role:
1. Alice reads the message from the "Message.txt" file. The message size must be equal to or greater than 32 bytes.
2. Alice reads the shared seed from the "SharedSeed.txt" file (32 bytes).
3. Alice generates the secret key from the shared seed using the ChaCha20 PRNG function from LibTomCrypt. The key size must match the message length.
4. Alice writes the Hex format of the key to a file named "Key.txt."
5. Alice XORs the message with the secret key to obtain the ciphertext (Ciphertext = Message XOR Key).
6. Alice writes the Hex format of the ciphertext to a file named "Ciphertext.txt."
7. Alice sends the ciphertext to Bob via ZeroMQ.
8. Alice anticipates an "acknowledgment" from Bob using ZeroMQ. The acknowledgment refers to the hash value of the original text, and Alice can match it with the hash of the original message using SHA256.
9. If the comparison is successful, Alice writes "Acknowledgment Successful" in a file called "Acknowledgment.txt." Otherwise, she records "Acknowledgment Failed."

### Bob's Role:
1. Bob receives the ciphertext from Alice via ZeroMQ.
2. Bob reads the shared seed from the "SharedSeed.txt" file (32 bytes).
3. Bob generates the secret key from the shared seed using the ChaCha20 PRNG function from LibTomCrypt. The key size must match the message length.
4. Bob XORs the received ciphertext with the secret key to obtain the plaintext (Plaintext = Ciphertext XOR Key).
5. Bob writes the decrypted plaintext to a file named "Plaintext.txt."
6. Bob hashes the plaintext using SHA256 and writes the Hex format of the hash to a file named "Hash.txt."
7. Finally, Bob sends the hash over ZeroMQ to Alice as an acknowledgment.

## Prerequisites

Before running the code, make sure you have the following installed:

- LibTomCrypt library
- ZeroMQ library

## Usage

1. Compile the Alice and Bob programs with the following commands:
   
   ```
   gcc alice.c -ltomcrypt -lzmq -o alice
   gcc bob.c -ltomcrypt -lzmq -o bob
   ```

2. Run the Alice and Bob programs for the first test files (you can replace `Message1.txt` and `SharedSeed1.txt` with your own filenames):

   ```
   ./alice Message1.txt SharedSeed1.txt
   ./bob SharedSeed1.txt
   ```

## Verification Script

A verification script is provided (`VerifyingYourSolution1.sh`) to test the correctness of your code with provided test files. To use the script, place `alice.c`, `bob.c`, the provided files, and the script in one folder and run the following command in the terminal:

```
bash VerifyingYourSolution1.sh
```

## File Descriptions

- `alice.c`: Alice's code for encrypting the message and sending it to Bob.
- `bob.c`: Bob's code for receiving the ciphertext from Alice, decrypting it, and sending an acknowledgment.
- `Message.txt`: Input file containing the message to be encrypted.
- `SharedSeed.txt`: Input file containing the shared seed for key generation.
- `Key.txt`: Output file where Alice writes the Hex format of the secret key.
- `Ciphertext.txt`: Output file where Alice writes the Hex format of the ciphertext.
- `Plaintext.txt`: Output file where Bob writes the decrypted plaintext.
- `Hash.txt`: Output file where Bob writes the Hex format of the hash of the plaintext.
- `Acknowledgment.txt`: Output file where Alice records the acknowledgment result.

## Note

- Ensure that the LibTomCrypt and ZeroMQ libraries are properly installed and configured on your system.
- The code provided here is a toy stream cipher implementation for educational purposes. It is not intended for production use.

Please feel free to reach out if you have any questions or need further assistance with this project.
