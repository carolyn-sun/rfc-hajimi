# RFC Hajimi Standard (RFC-HJM)

_“哈基米咯南北绿豆阿西噶哈呀库那路～”_

**Version:** 0.1

**Status:** Experimental Standard

**Author:** RFC Hajimi Standard Committee

**Date:** January 3 2026

---

## 1. Abstract

RFC Hajimi (Request for Comments: Hajimi) defines a robust, character-based encoding and cryptographic framework. It transforms arbitrary binary data into a unique 16-character alphabet derived from cultural phonetic symbols. Beyond simple encoding, this standard specifies a multi-tier security architecture including symmetric XOR obfuscation, GPG-style asymmetric encryption, and Ed25519-based digital signatures.

The goal of RFC Hajimi is to provide a standardized, character-based method for data handling while maintaining the mathematical rigor of modern cryptography.

---

## 2. Terminology

- **HJM-16**: The core 16-character alphabet.
- **Nibble**: A 4-bit unit of data (half a byte).
- **HJM-Enc**: The process of converting binary data to Hajimi characters.
- **HJM-Sign**: The process of generating an Ed25519 signature in Hajimi format.
- **Obfuscation Key**: A 8-bit key used for symmetric XOR operations.
- **Symmetric Hajimi (对称基米)**: The data format after standard HJM-16 encoding and optional symmetric XOR obfuscation.
- **Asymmetric Hajimi (非对称基米)**: The data format representing results of asymmetric operations (RSA, Ed25519, X25519), including encrypted payloads and digital signatures.

---

## 3. The Hajimi Alphabet (HJM-16)

The alphabet consists of 16 specific Unicode characters. Each character corresponds to a hexadecimal value from `0x0` to `0xF`.

| Hex     | Character | Meaning/Phonetic | Hex     | Character | Meaning/Phonetic |
| :------ | :-------- | :--------------- | :------ | :-------- | :--------------- |
| **0x0** | 哈        | Ha               | **0x8** | 阿        | A                |
| **0x1** | 基        | Ji               | **0x9** | 西        | Xi               |
| **0x2** | 米        | Mi               | **0xA** | 噶        | Ga               |
| **0x3** | 咯        | Lo               | **0xB** | 呀        | Ya               |
| **0x4** | 南        | Nan              | **0xC** | 库        | Ku               |
| **0x5** | 北        | Bei              | **0xD** | 那        | Na               |
| **0x6** | 绿        | Lv               | **0xE** | 路        | Lu               |
| **0x7** | 豆        | Dou              | **0xF** | ～        | (Wave/End)       |

---

## 4. Encoding Procedure

### 4.1. Binary to Hajimi

1.  **Decomposition**: Take the input byte stream. For each byte, split it into two 4-bit nibbles.
2.  **Order**: The **Most Significant Nibble (MSN)** is processed first, followed by the **Least Significant Nibble (LSN)**.
3.  **Mapping**: Look up each nibble in the HJM-16 table and append the character to the output string.

### 4.2. Hajimi to Binary

1.  **Validation**: Ensure the input string consists only of valid HJM-16 characters and has an even length.
2.  **Reverse Mapping**: Convert each character back to its 4-bit value.
3.  **Recomposition**: Combine two 4-bit values (High << 4 | Low) to reconstruct the original byte.

---

## 5. Cryptographic Layers

### 5.1. Layer 1: Symmetric XOR (Obfuscation)

Provides a basic level of privacy by XORing each input byte with an 8-bit `key` before encoding.
`secret_byte = original_byte ^ (key % 256)`

### 5.2. Layer 2: Asymmetric RSA (Confidentiality)

Designed for secure messaging between two parties.

- **Public Key**: (n, e) - Used by the sender to encrypt.
- **Private Key**: (n, d) - Used by the receiver to decrypt.
- **Standard**: RFC Hajimi uses a simplified RSA implementation where session data is serialized and then HJM-16 encoded.

### 5.3. Layer 3: Ed25519 EdDSA (Authentication)

The highest tier of the standard, providing non-repudiation and integrity via the Ed25519 signature algorithm.

- **Curve**: Edwards25519 ($x^2 + y^2 = 1 + d x^2 y^2$ over $\mathbb{F}_{2^{255}-19}$).
- **Signature Length**: 64 bytes (128 Hajimi characters).
- **Public Key Length**: 32 bytes (64 Hajimi characters).

---

## 6. Official Julia Implementation Guide

The official reference implementation is provided via the `RFCHajimi` module.

### 6.1. Quick Start (Shell)

To launch a Julia environment with the official standard pre-loaded:

```bash
julia --project="." -i -e 'include("src/RFCHajimi.jl"); using .RFCHajimi'
```

### 6.2. Development Setup

If you are integrating RFC Hajimi into a larger Julia project:

1.  **Activate Project**:
    ```julia
    using Pkg
    Pkg.activate("/path/to/rfc-hajimi")
    Pkg.instantiate()
    ```
2.  **Load Source**:
    ```julia
    include("src/RFCHajimi.jl")
    using .RFCHajimi
    ```

### 6.3. Symmetric Hajimi (Encoding & XOR)

```julia
# Standard HJM-16 Encoding
cipher = hjm_encode("🐎 哈基米～哈基米～")

# Keyed Symmetric Hajimi (Level 1)
key = 127
secret = hjm_encode("喝了蜂蜜就能更快！", key=key)
plain = hjm_decode(secret, key=key)
```

### 6.4. Asymmetric Hajimi (Level 2-4)

#### Digital Signatures & Identity (Level 3)

The official way to establish a verified identity.

```julia
# 1. Start the interactive identity wizard
# This will ask for your Name and Email Address
sk, pk, id_str = hjm_create_identity()

# 2. Export your PUBLIC key for community submission
hjm_export_public_key(pk, "my_identity.hjm-pub", identity=id_str)

# 3. Export your PRIVATE key (with interactive confirmation)
# Note: Private keys can only be saved to the current directory.
hjm_export_private_key(sk, "my_identity.key")

# 4. Sign a message using your private key
sig = hjm_sign("I am authorized.", sk)

# 5. Verify any signature
is_valid = hjm_verify("I am authorized.", sig, pk)
```

#### Diffie-Hellman Key Exchange (X25519)

Used for establishing a shared secret over an insecure channel.

```julia
# Alice and Bob generate temporary DH keys
sk_a, pk_a = hjm_dh_generate_keys()
sk_b, pk_b = hjm_dh_generate_keys()

# Compute shared secret
shared_secret = hjm_dh_shared_secret(sk_a, pk_b)
```

#### Binary File Encryption (Level 1)

```julia
hjm_encrypt_file("secret.pdf", "secret.hjm", key=123)
hjm_decrypt_file("secret.hjm", "restored.pdf", key=123)
```

#### Key Import (Hajimi Armor)

```julia
# Importing back from armored string
imported_sk = hjm_import_key(read("my_identity.key", String))
```

---

## 7. Hajimi CLI

A reference browser-based transformation tool is available at `cli.html`. This tool allows for instant encoding and decoding of HJM-16 streams without requiring a Julia environment.

---

## 8. Security Considerations

- The symmetric XOR layer is intended for obfuscation.
- **Level 2 (RSA)**: Reference implementation uses small primes for demonstration; production scripts should use hardened RSA.
- **Level 3 (Ed25519)** & **Level 4 (X25519)**: Implemented following RFC 8032 and Curve25519 specifications for cryptographic strength.
- RFC Hajimi provides a robust framework for character-oriented cryptographic operations.

---

## 9. Future Work

- [ ] Implement HJM-Auth (Hajimi-based OAuth 2.0 extension).
- [ ] Hardware Security Module (HSM) prototype for "Physical Hajimi Keys".

---

## 10. Disclaimer

1.  **NO LIABILITY**: The RFC Hajimi Standard Committee and contributors are not responsible for any data, content, or consequences resulting from the use of this encoding or its cryptographic layers. Users assume all risks associated with data loss, corruption, or exposure.
2.  **CRYPTO-SECURITY**: Based on current mathematical reasoning and the security properties of the underlying primitives (RSA, X25519, Ed25519), it is computationally infeasible to reverse or "break" the content generated by a valid secret key without authorization. However, this is not a guarantee against future mathematical breakthroughs or implementation-specific vulnerabilities.
3.  **EXPERIMENTAL STATUS**: This standard is presented as an experimental security project. It should be used with appropriate caution in mission-critical environments.

---
