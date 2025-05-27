# Secure Signature Compression using RSA, SHA-256, and Huffman Coding

## Overview

This project demonstrates a simple cryptographic workflow involving:
- Generating RSA key pairs
- Creating a digital signature using SHA-256 and RSA
- Compressing the binary signature using Huffman Coding

The program takes a user-input message, signs it using a freshly generated RSA key, and then compresses the raw binary signature using Huffman encoding.

---

## Features

- 🔐 **RSA Key Generation** (2048-bit)
- 🧾 **SHA-256 Hashing** for digital integrity
- ✍️ **Digital Signature Creation** using RSA
- 🗜️ **Huffman Coding** for binary compression of the signature
- 📏 Output of:
  - Original Signature in hexadecimal
  - Length of the signature in bits
  - Huffman-encoded signature as a bit string
  - Compressed signature length

---

## Dependencies

Make sure you have OpenSSL installed:

```bash
sudo apt-get install libssl-dev
