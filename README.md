# BitCascade 🔐

A custom symmetric encryption algorithm implementation with graphical interface, designed for educational purposes to demonstrate cryptographic principles.

## Features ✨

- **Custom Encryption Algorithm**: Original symmetric cipher with confusion and diffusion techniques
- **Graphical Interface**: User-friendly SFML-based GUI
- **Block Processing**: Handles texts of any length using 8-byte blocks
- **File Operations**: Save and load encrypted texts
- **Key Validation**: Detects incorrect decryption keys
- **Educational Focus**: Perfect for learning cryptography concepts

## Algorithm Overview 🧠

### Security Characteristics
- **Strong Key Sensitivity**: Minimal key changes produce completely different ciphertexts
- **Effective Diffusion**: Single plaintext bit alterations affect multiple ciphertext bytes  
- **Pattern Resistance**: Obscures statistical relationships between plaintext and ciphertext
- **Multi-Round Protection**: 5 encryption rounds with layered security
- **Dynamic Subkeys**: Unique subkeys per round derived from key, round number, and position

### Technical Design
- **Block Size**: 8-byte blocks with PKCS7 padding
- **Rounds**: 5 encryption/decryption rounds
- **Confusion Phase**: XOR operations with dynamic subkeys and positional variations
- **Diffusion Phase**: Bit rotations, sequential XOR mixing, and zig-zag transposition

## Installation & Usage 🚀

### Prerequisites
- C++ Compiler (GCC, Clang, or MSVC)
- SFML Library
- CMake (optional)

### Building
```bash
git clone https://github.com/JimenaD-creator/Encryption-Algorithm.git
cd Encryption-Algorithm
```
### Running
```bash
./gui.exe
```
### Usage examples 💡
### Encryption
- Launch the application
- Select "Encrypt Text"
- Enter plaintext (max 100 characters)
- Provide encryption key (max 16 characters)
- Save encrypted output to file

### Decryption
- Choose "Decrypt Text"
- Select encrypted file
- Enter decryption key
- System validates key and decrypts content

Note: This implementation is for educational purposes and should not be used for securing sensitive real-world data.
