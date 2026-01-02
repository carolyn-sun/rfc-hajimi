# Community Public Keys

This directory serves as the official registry for **RFC Hajimi** public keys shared by the community.

## How to contribute your key

1. Generate your Ed25519 or RSA key pair using `RFCHajimi.jl`.
2. Export your **PUBLIC** key using the `hjm_export_key` function.
3. Save it as a `.hjm-pub` file in this directory.
4. **Mandatory Identity**: Your file must include your **primary email address** at the top (plain text) to establish identity.
5. Name the file as `username.hjm-pub`.

## File Format

Keys should be in the "Hajimi Armor" format, preceded by your identity line:

```text
Identity: <your-email@example.com>

-----BEGIN HAJIMI PUBLIC KEY-----
... (Hajimi Characters) ...
-----END HAJIMI PUBLIC KEY-----
```

---

_By placing your public key here, you allow others to verify your signatures and send you encrypted messages within the Hajimi ecosystem._
