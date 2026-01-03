if !isdefined(Main, :RFCHajimi)
    include("../src/RFCHajimi.jl")
end
using .RFCHajimi
using Test
using Random

@testset "RFC Hajimi Comprehensive Test Suite" begin

    @testset "Core Symmetric Logic" begin
        # Basic Roundtrip
        messages = [
            "Hello Hajimi!",
            "喝了蜂蜜就能更快！",
            "🐎 哈基米～哈基米～哈基米～",
            "", # Empty string
            "A" ^ 100 # Long string
        ]
        
        for msg in messages
            # No key
            encoded = hjm_encode(msg)
            @test hjm_decode(encoded) == msg
            
            # With key
            key = rand(0:1000)
            encoded_k = hjm_encode(msg, key=key)
            @test hjm_decode(encoded_k, key=key) == msg
            
            # Key mismatch
            if msg != ""
                @test hjm_decode(encoded_k, key=key+1) != msg
            end
        end
    end

    @testset "RSA-like Asymmetric Encryption" begin
        keys = hjm_generate_keys()
        msg = "Top Secret RFC Document"
        
        cipher = hjm_asym_encrypt(msg, keys.public_key)
        @test hjm_asym_decrypt(cipher, keys.private_key) == msg
        
        # Test large data
        large_msg = "x" ^ 500
        cipher_large = hjm_asym_encrypt(large_msg, keys.public_key)
        @test hjm_asym_decrypt(cipher_large, keys.private_key) == large_msg
    end

    @testset "Ed25519 Digital Signatures" begin
        sk, pk = hjm_generate_ed_keys()
        message = "I hereby sign this Hajimi Standard."
        
        signature = hjm_sign(message, sk)
        @test hjm_verify(message, signature, pk) == true
        
        # Tampering with message
        @test hjm_verify(message * " tampered", signature, pk) == false
        
        # Tampering with signature (flip last char if possible)
        sig_chars = collect(signature)
        last_char = sig_chars[end]
        # find another char in alphabet
        sig_chars[end] = last_char == '哈' ? '基' : '哈'
        @test hjm_verify(message, String(sig_chars), pk) == false
        
        # Wrong public key
        sk2, pk2 = hjm_generate_ed_keys()
        @test hjm_verify(message, signature, pk2) == false
    end

    @testset "X25519 Diffie-Hellman" begin
        # Round 1
        sk_a, pk_a = hjm_dh_generate_keys(save=false)
        sk_b, pk_b = hjm_dh_generate_keys(save=false)
        
        ss_a = hjm_dh_shared_secret(sk_a, pk_b)
        ss_b = hjm_dh_shared_secret(sk_b, pk_a)
        
        @test ss_a == ss_b
        @test length(ss_a) == 64 # 32 bytes * 2
        
        # Different keys should produce different secrets
        sk_c, pk_c = hjm_dh_generate_keys(save=false)
        ss_c = hjm_dh_shared_secret(sk_c, pk_a)
        @test ss_c != ss_a
    end

    @testset "Key Armor (Export/Import)" begin
        sk, pk = hjm_generate_ed_keys()
        
        # Test Public Export with Identity
        pub_file = "test_pk.hjm-pub"
        hjm_export_public_key(pk, pub_file, identity="Test User <test@example.com>")
        @test isfile(pub_file)
        content = read(pub_file, String)
        @test contains(content, "Identity: Test User <test@example.com>")
        @test hjm_import_key(content) == pk
        rm(pub_file)
        
        # Test Private Export Security: Path Restriction
        @test_throws ArgumentError hjm_export_private_key(sk, "subdir/test.key")
        @test_throws ArgumentError hjm_export_private_key(sk, "/tmp/test.key")
        
        # Test Private Export: Aborted (Mocking NO)
        priv_file = "test_sk.key"
        # We wrap the call and redirect stdin to simulate user input
        stdin_original = stdin
        try
            rd, wr = redirect_stdin()
            write(wr, "NO\n")
            hjm_export_private_key(sk, priv_file)
            @test !isfile(priv_file)
        finally
            redirect_stdin(stdin_original)
        end

        # Test Private Export: Success (Mocking YES)
        try
            rd, wr = redirect_stdin()
            write(wr, "YES\n")
            hjm_export_private_key(sk, priv_file)
            @test isfile(priv_file)
            @test hjm_import_key(read(priv_file, String)) == sk
        finally
            redirect_stdin(stdin_original)
            rm(priv_file, force=true)
        end
        
        # Test Automatic Identity Creation Saving (Level 3)
        try
            rd, wr = redirect_stdin()
            write(wr, "3\nAuto Tester\nautotester@example.com\n")
            sk_id, pk_id, id_s = hjm_create_identity()
            
            @test isfile("auto_tester.hjm-pub")
            @test isfile("auto_tester.hjm-key")
            @test hjm_import_key(read("auto_tester.hjm-pub", String)) == pk_id
        finally
            redirect_stdin(stdin_original)
            rm("auto_tester.hjm-pub", force=true)
            rm("auto_tester.hjm-key", force=true)
        end

        # Test Automatic Exchange Key Creation Saving (Level 4)
        try
            rd, wr = redirect_stdin()
            write(wr, "4\ntest_session\n")
            sk_dh, pk_dh, id_dh = hjm_create_identity()
            
            @test isfile("test_session_dh.hjm-pub")
            @test isfile("test_session_dh.hjm-key")
            @test hjm_import_key(read("test_session_dh.hjm-pub", String)) == pk_dh
        finally
            redirect_stdin(stdin_original)
            rm("test_session_dh.hjm-pub", force=true)
            rm("test_session_dh.hjm-key", force=true)
        end
        
        # Import should handle messy formatting (extra whitespace/newlines)
        armored_pk = RFCHajimi._generate_armor(pk, "PUBLIC")
        messy = "\n\n  " * armored_pk * "   \n\n"
        imported = hjm_import_key(messy)
        @test imported == pk
    end

    @testset "Binary File Encryption (Level 1)" begin
        # Create a dummy binary file
        src = "test_src.bin"
        dest = "test_dest.hjm"
        back = "test_back.bin"
        
        data = rand(UInt8, 1024)
        write(src, data)
        
        try
            key = 99
            hjm_encrypt_file(src, dest, key=key)
            @test isfile(dest)
            
            hjm_decrypt_file(dest, back, key=key)
            @test read(back) == data
        finally
            # Cleanup
            rm(src, force=true)
            rm(dest, force=true)
            rm(back, force=true)
        end
    end

    @testset "Error Handling & Limits" begin
        # Valid alphabet: 哈基米咯南北绿豆阿西噶呀库那路～
        
        # Odd length
        @test_throws ArgumentError hjm_decode("哈基米")
        
        # Non-standard characters
        @test_throws ArgumentError hjm_decode("哈基A米")
        
        # RSA Decryption with wrong ciphertext
        keys = hjm_generate_keys()
        @test_throws Exception hjm_asym_decrypt("哈基", keys.private_key)
        
        # Ed25519 verify with invalid signature format
        sk, pk = hjm_generate_ed_keys()
        @test hjm_verify("test", "哈基", pk) == false # Too short
    end

end
