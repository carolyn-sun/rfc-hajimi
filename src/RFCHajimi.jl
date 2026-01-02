module RFCHajimi

using Random
using Serialization
using SHA

export hjm_encode, hjm_decode, hjm_generate_keys, hjm_asym_encrypt, hjm_asym_decrypt, HajimiKeyPair
export hjm_generate_ed_keys, hjm_sign, hjm_verify
export hjm_dh_generate_keys, hjm_dh_shared_secret
export hjm_export_key, hjm_import_key
export hjm_export_public_key, hjm_export_private_key
export hjm_encrypt_file, hjm_decrypt_file
export hjm_create_identity, julia_main

"""
    julia_main() -> Cint
Entry point for the compiled standalone Hajimi application.
"""
function julia_main()::Cint
    try
        if isempty(ARGS)
            println("RFC Hajimi Standard CLI (v0.1)")
            println("Usage: hjm <command> [options]")
            println("\nAvailable Commands:")
            println("  create         Start the interactive key generation wizard (Level 3/4)")
            println("  encode <msg>   Encode plaintext message to HJM-16")
            println("  decode <hjm>   Decode HJM-16 stream to plaintext")
            println("  sign <msg> <k> Sign a message using a private key file")
            println("  verify <m><s><p> Verify a signature with a public key")
            return 0
        end

        cmd = ARGS[1]
        if cmd == "create"
            hjm_create_identity()
        elseif cmd == "encode" && length(ARGS) >= 2
            println(hjm_encode(ARGS[2]))
        elseif cmd == "decode" && length(ARGS) >= 2
            println(hjm_decode(ARGS[2]))
        elseif cmd == "sign" && length(ARGS) >= 3
            # Load private key from file
            sk = hjm_import_key(read(ARGS[3], String))
            println(hjm_sign(ARGS[2], sk))
        elseif cmd == "verify" && length(ARGS) >= 4
            # verify <msg> <sig> <pk_file_or_string>
            pk = isfile(ARGS[4]) ? hjm_import_key(read(ARGS[4], String)) : ARGS[4]
            isValid = hjm_verify(ARGS[2], ARGS[3], pk)
            println(isValid ? "✓ OK" : "✗ FAILED")
        else
            println("[Error] Unknown command or missing arguments.")
            return 1
        end
    catch e
        println("[Error] ", e)
        return 1
    end
    return 0
end

"""
    ALPHABET
RFC Hajimi Standard Characters (16 bits).
Index from 0 (哈) to 15 (～).
"""
const ALPHABET = ['哈', '基', '米', '咯', '南', '北', '绿', '豆', 
                  '阿', '西', '噶', '呀', '库', '那', '路', '～']

const CHAR_MAP = Dict(c => UInt8(i-1) for (i, c) in enumerate(ALPHABET))

# --- Internal Helper Functions ---

function _to_hjm(bytes::Vector{UInt8})
    output = Vector{Char}(undef, length(bytes) * 2)
    for i in 1:length(bytes)
        output[2i-1] = ALPHABET[(bytes[i] >> 4) + 1]
        output[2i]   = ALPHABET[(bytes[i] & 0x0f) + 1]
    end
    return String(output)
end

function _from_hjm(hjm_str::String)
    # Remove any whitespace or armor lines if present during import
    clean_str = filter(c -> c in ALPHABET, hjm_str)
    chars = collect(clean_str)
    if length(chars) % 2 != 0
        throw(ArgumentError("RFC Hajimi data length must be even."))
    end
    out = Vector{UInt8}(undef, length(chars) ÷ 2)
    for i in 1:2:length(chars)
        high = get(CHAR_MAP, chars[i], nothing)
        low  = get(CHAR_MAP, chars[i+1], nothing)
        if high === nothing || low === nothing
            throw(ArgumentError("Invalid RFC Hajimi character found."))
        end
        out[(i+1)÷2] = (high << 4) | low
    end
    return out
end

# --- Symmetric Encryption & Encoding ---

"""
    hjm_encode(input::String; key::Integer=0) -> String

Encodes input string to RFC Hajimi format. `key` is used for XOR obfuscation.
"""
function hjm_encode(input::String; key::Integer=0)
    bytes = Vector{UInt8}(input)
    k = UInt8(key % 256)
    obfuscated = [b ⊻ k for b in bytes]
    return _to_hjm(obfuscated)
end

"""
    hjm_decode(cipher::String; key::Integer=0) -> String

Decodes RFC Hajimi string back to original.
"""
function hjm_decode(cipher::String; key::Integer=0)
    bytes = _from_hjm(cipher)
    k = UInt8(key % 256)
    original = [b ⊻ k for b in bytes]
    return String(original)
end

# --- Montgomery Curve (X25519) for DH ---

const Q = BigInt(2)^255 - 19
const A24 = BigInt(121665)

function cswap(swap, x_2, x_3)
    dummy = (swap * (x_2 - x_3)) % Q
    x_2 = (x_2 - dummy) % Q
    x_3 = (x_3 + dummy) % Q
    return x_2, x_3
end

function x25519(scalar::BigInt, point::BigInt)
    x_1 = point
    x_2, z_2 = BigInt(1), BigInt(0)
    x_3, z_3 = point, BigInt(1)
    swap = 0
    for t in 254:-1:0
        k_t = (scalar >> t) & 1
        swap = xor(swap, k_t)
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % Q
        AA = powermod(A, 2, Q)
        B = (x_2 - z_2) % Q
        BB = powermod(B, 2, Q)
        E = (AA - BB) % Q
        C = (x_3 + z_3) % Q
        D = (x_3 - z_3) % Q
        DA = (D * A) % Q
        CB = (C * B) % Q
        x_3 = powermod(DA + CB, 2, Q)
        z_3 = (x_1 * powermod(DA - CB, 2, Q)) % Q
        x_2 = (AA * BB) % Q
        z_2 = (E * (AA + A24 * E)) % Q
    end
    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    return (x_2 * invmod(z_2, Q)) % Q
end

"""
    hjm_dh_generate_keys(; save::Bool=true) -> (private_hjm, public_hjm)
Generates X25519 keys for Diffie-Hellman exchange.
Automatically saves to 'dh_temp.hjm-pub' and 'dh_temp.hjm-key' if save=true.
"""
function hjm_dh_generate_keys(; save::Bool=true)
    sk_bytes = rand(UInt8, 32)
    sk_bytes[1] &= 248
    sk_bytes[32] &= 127
    sk_bytes[32] |= 64
    sk = decode_int(sk_bytes)
    pk = x25519(sk, BigInt(9))
    
    sk_hjm = _to_hjm(sk_bytes)
    pk_hjm = _to_hjm(encode_int(pk, 32))
    
    if save
        hjm_export_public_key(pk_hjm, "dh_temp.hjm-pub")
        # Save private key bypassing the YES confirmation for automatic flow
        armor = _generate_armor(sk_hjm, "PRIVATE")
        write("dh_temp.hjm-key", armor)
        println("[Success] DH keys automatically saved to dh_temp.hjm-pub/key")
    end
    
    return sk_hjm, pk_hjm
end

"""
    hjm_dh_shared_secret(sk_hjm::String, other_pk_hjm::String) -> secret_hjm
Computes the shared secret using X25519.
"""
function hjm_dh_shared_secret(sk_hjm, other_pk_hjm)
    sk = decode_int(_from_hjm(sk_hjm))
    other_pk = decode_int(_from_hjm(other_pk_hjm))
    shared = x25519(sk, other_pk)
    return _to_hjm(encode_int(shared, 32))
end

# --- Ed25519 Digital Signatures (Standard RFC 8032) ---
# ... (Calculations P, L, D, I, etc. assumed to be stay unchanged above or below)

# Note: P is already defined above in X25519 as Q. I'll reuse or unify.
const L = BigInt(2)^252 + BigInt(27742317777372353535851937790883648493)
const D_ED = -121665 * invmod(BigInt(121666), Q) % Q
const I_ED = powermod(BigInt(2), (Q - 1) ÷ 4, Q)

function x_from_y(y::BigInt, sign::Int)
    x2 = (y^2 - 1) * invmod(D_ED * y^2 + 1, Q) % Q
    x = powermod(x2, (Q + 3) ÷ 8, Q)
    if (x^2 - x2) % Q != 0
        x = (x * I_ED) % Q
    end
    if (x % 2 == 1 && sign == 0) || (x % 2 == 0 && sign == 1)
        x = Q - x
    end
    return x
end

const B_Y = 4 * invmod(BigInt(5), Q) % Q
const B_X = x_from_y(B_Y, 0)
const BASE_POINT = (B_X % Q, B_Y % Q)

function point_add(P1, P2)
    x1, y1 = P1
    x2, y2 = P2
    x3 = (x1*y2 + x2*y1) * invmod(1 + D_ED*x1*x2*y1*y2, Q) % Q
    y3 = (y1*y2 + x1*x2) * invmod(1 - D_ED*x1*x2*y1*y2, Q) % Q
    return (x3, y3)
end

function point_mul(P1, n)
    R = (BigInt(0), BigInt(1))
    n = n % L
    while n > 0
        if n % 2 == 1
            R = point_add(R, P1)
        end
        P1 = point_add(P1, P1)
        n ÷= 2
    end
    return R
end

function encode_int(n::BigInt, len::Int=32)
    bytes = Vector{UInt8}(undef, len)
    for i in 1:len
        bytes[i] = UInt8(n & 0xff)
        n >>= 8
    end
    return bytes
end

function decode_int(bytes::Vector{UInt8})
    n = BigInt(0)
    for i in length(bytes):-1:1
        n = (n << 8) | bytes[i]
    end
    return n
end

function encode_point(P_point)
    x, y = P_point
    bytes = encode_int(y, 32)
    if x % 2 == 1
        bytes[32] |= 0x80
    end
    return bytes
end

function decode_point(bytes::Vector{UInt8})
    y_bytes = copy(bytes)
    y_bytes[32] &= 0x7f
    y = decode_int(y_bytes)
    sign = (bytes[32] & 0x80) != 0 ? 1 : 0
    x = x_from_y(y, sign)
    return (x, y)
end

"""
    hjm_generate_ed_keys() -> (private_key_hjm, public_key_hjm)
Generates Ed25519 keys for RFC Hajimi.
"""
function hjm_generate_ed_keys()
    sk = rand(UInt8, 32)
    h = sha512(sk)
    a = decode_int(h[1:32])
    # Pruning bits
    a &= ~(BigInt(7))
    a &= ~(BigInt(1) << 254)
    a |= (BigInt(1) << 254)
    
    A = point_mul(BASE_POINT, a)
    pk = encode_point(A)
    
    return _to_hjm(sk), _to_hjm(pk)
end

"""
    hjm_create_identity()
Interactive wizard to generate RFC Hajimi keys. 
Offers a choice between Level 3 (Identity/Signature) and Level 4 (Key Exchange). 
Automatically handles metadata association and file saving.
"""
function hjm_create_identity()
    println("RFC Hajimi Standard - Secure Key Generation Wizard")
    println("===================================================")
    println("Select Key Type:")
    println(" [3] Level 3: Identity Key (Ed25519 - For Signing/Verification)")
    println(" [4] Level 4: Exchange Key (X25519 - For Diffie-Hellman Key Exchange)")
    print("\nEnter choice (3 or 4): ")
    choice = strip(readline())
    
    if choice == "3"
        println("\n--- Generating Level 3 Identity Key ---")
        print("Enter Full Name: ")
        nameInput = strip(readline())
        print("Enter Email Address: ")
        email = strip(readline())
        
        if isempty(nameInput) || isempty(email)
            throw(ArgumentError("Formal identity requires both Name and Email Address."))
        end
        
        sk, pk = hjm_generate_ed_keys()
        id_str = "$nameInput <$email>"
        
        safe_name = replace(lowercase(nameInput), r"[^a-z0-9_-]" => "_")
        pub_file = "$safe_name.hjm-pub"
        key_file = "$safe_name.hjm-key"
        
        hjm_export_public_key(pk, pub_file, identity=id_str)
        write(key_file, _generate_armor(sk, "PRIVATE"))
        
        println("\n[Success] Identity keys generated for: $id_str")
        println("[System] Files saved: $pub_file, $key_file")
        return sk, pk, id_str

    elseif choice == "4"
        println("\n--- Generating Level 4 Exchange Key ---")
        print("Enter a Session/Owner Name (for filename): ")
        session_name = replace(lowercase(strip(readline())), r"[^a-z0-9_-]" => "_")
        if isempty(session_name) session_name = "dh_session" end
        
        sk, pk = hjm_dh_generate_keys(save=false)
        
        pub_file = "$(session_name)_dh.hjm-pub"
        key_file = "$(session_name)_dh.hjm-key"
        
        hjm_export_public_key(pk, pub_file)
        write(key_file, _generate_armor(sk, "PRIVATE"))
        
        println("\n[Success] Diffie-Hellman exchange keys generated.")
        println("[System] Files saved: $pub_file, $key_file")
        return sk, pk, "DH Session: $session_name"
    else
        println("[Error] Invalid choice. Aborting.")
        return nothing
    end
end

"""
    hjm_sign(message::String, sk_hjm::String) -> signature_hjm
Signs a message using RFC Hajimi Ed25519 standard.
"""
function hjm_sign(message::String, sk_hjm::String)
    sk = _from_hjm(sk_hjm)
    h = sha512(sk)
    a = decode_int(h[1:32])
    a &= ~(BigInt(7))
    a &= ~(BigInt(1) << 254)
    a |= (BigInt(1) << 254)
    
    prefix = h[33:64]
    m_bytes = Vector{UInt8}(message)
    r = decode_int(sha512(vcat(prefix, m_bytes))) % L
    
    R_point = point_mul(BASE_POINT, r)
    R_bytes = encode_point(R_point)
    
    A = point_mul(BASE_POINT, a)
    pk_bytes = encode_point(A)
    
    k = decode_int(sha512(vcat(R_bytes, pk_bytes, m_bytes))) % L
    s = (r + k * a) % L
    
    sig = vcat(R_bytes, encode_int(s, 32))
    return _to_hjm(sig)
end

"""
    hjm_verify(message::String, sig_hjm::String, pk_hjm::String) -> Bool
Verifies an RFC Hajimi Ed25519 signature.
"""
function hjm_verify(message::String, sig_hjm::String, pk_hjm::String)
    sig = try _from_hjm(sig_hjm) catch; return false end
    pk_bytes = try _from_hjm(pk_hjm) catch; return false end
    m_bytes = Vector{UInt8}(message)
    
    if length(sig) != 64 return false end
    
    R_bytes = sig[1:32]
    S = decode_int(sig[33:64])
    if S >= L return false end
    
    R_point = try decode_point(R_bytes) catch; return false end
    A_point = try decode_point(pk_bytes) catch; return false end
    
    k = decode_int(sha512(vcat(R_bytes, pk_bytes, m_bytes))) % L
    
    P1 = point_mul(BASE_POINT, S)
    P2 = point_add(R_point, point_mul(A_point, k))
    
    return P1 == P2
end

# --- Key Export/Import (Hajimi Armor) ---

"""
    hjm_export_key(key_hjm::String, type::String="PRIVATE"; identity::String="") -> String
Internal helper to generate Hajimi Armor string.
"""
function _generate_armor(key_hjm::String, type::String; identity::String="")
    header = "-----BEGIN HAJIMI $(uppercase(type)) KEY-----"
    footer = "-----END HAJIMI $(uppercase(type)) KEY-----"
    chars = collect(key_hjm)
    lines = String[]
    for i in 1:32:length(chars)
        push!(lines, String(chars[i:min(i+31, end)]))
    end
    armor = join([header; lines; footer], "\n")
    return isempty(identity) ? armor : "Identity: $identity\n\n$armor"
end

"""
    hjm_export_public_key(pk_hjm::String, filename::String; identity::String="")
Exports a public key to a file.
"""
function hjm_export_public_key(pk_hjm::String, filename::String; identity::String="")
    armor = _generate_armor(pk_hjm, "PUBLIC", identity=identity)
    write(filename, armor)
    println("[Success] Public key exported to: $filename")
end

"""
    hjm_export_private_key(sk_hjm::String, filename::String)
Exports a private key to a file in the current directory only.
Requires secondary confirmation.
"""
function hjm_export_private_key(sk_hjm::String, filename::String)
    # Security: Ensure filename is in current directory (no path separators)
    if occursin("/", filename) || occursin("\\", filename)
        throw(ArgumentError("Security: Private keys can only be exported to the current directory (no paths)."))
    end
    
    println("\n[!] WARNING: You are about to export a PRIVATE KEY.")
    println("This file grant full access to your identity/data.")
    print("Are you absolutely sure? (Type 'YES' to confirm): ")
    confirm = strip(readline())
    
    if confirm == "YES"
        armor = _generate_armor(sk_hjm, "PRIVATE")
        write(filename, armor)
        println("[CRITICAL] Private key successfully exported to: $filename")
        println("Keep this file offline and safe.")
    else
        println("[Aborted] Export cancelled by user.")
    end
end

"""
    hjm_import_key(armored_key::String) -> String
Imports a key from Hajimi Armor.
"""
function hjm_import_key(armored_key::String)
    lines = split(strip(armored_key), "\n")
    # Filter out armor markers AND Identity markers
    data_lines = filter(lines) do l
        sl = strip(l)
        !startswith(sl, "-----") && !startswith(sl, "Identity:") && !isempty(sl)
    end
    return join([strip(l) for l in data_lines], "")
end

# --- File Encryption/Decryption ---

"""
    hjm_encrypt_file(src::String, dest::String; key::Integer=0)
Encrypts a file and saves the result as Hajimi characters.
"""
function hjm_encrypt_file(src::String, dest::String; key::Integer=0)
    bytes = read(src)
    k = UInt8(key % 256)
    obs = [b ⊻ k for b in bytes]
    hjm_str = _to_hjm(obs)
    write(dest, hjm_str)
end

"""
    hjm_decrypt_file(src::String, dest::String; key::Integer=0)
Decrypts a Hajimi-encoded file back to its original binary form.
"""
function hjm_decrypt_file(src::String, dest::String; key::Integer=0)
    hjm_str = read(src, String)
    bytes = _from_hjm(hjm_str)
    k = UInt8(key % 256)
    original = [b ⊻ k for b in bytes]
    write(dest, original)
end

# --- Asymmetric Encryption (GPG-style RSA) ---

struct HajimiKeyPair
    public_key::Tuple{BigInt, BigInt}  # (n, e)
    private_key::Tuple{BigInt, BigInt} # (n, d)
end

"""
    hjm_generate_keys()
Generates an RFC Hajimi Public/Private Key Pair (RSA).
"""
function hjm_generate_keys()
    p, q = BigInt(61), BigInt(53)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = BigInt(65537)
    d = invmod(e, phi)
    return HajimiKeyPair((n, e), (n, d))
end

"""
    hjm_asym_encrypt(plain_text::String, pub_key)
Encrypts text using RSA and encodes in RFC Hajimi.
"""
function hjm_asym_encrypt(plain_text::String, pub_key)
    n, e = pub_key
    bytes = Vector{UInt8}(plain_text)
    cipher_ints = [powermod(BigInt(b), e, n) for b in bytes]
    buf = IOBuffer()
    serialize(buf, cipher_ints)
    return _to_hjm(take!(buf))
end

"""
    hjm_asym_decrypt(hjm_str::String, priv_key)
Decrypts RSA encoded RFC Hajimi text.
"""
function hjm_asym_decrypt(hjm_str::String, priv_key)
    n, d = priv_key
    raw_bytes = _from_hjm(hjm_str)
    buf = IOBuffer(raw_bytes)
    cipher_ints = deserialize(buf)
    plain_bytes = UInt8[UInt8(powermod(c, d, n)) for c in cipher_ints]
    return String(plain_bytes)
end

end # module
