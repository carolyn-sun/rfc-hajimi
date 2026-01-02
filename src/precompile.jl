# src/precompile.jl
using RFCHajimi

# Run core functions once to precompile them during build
hjm_encode("Precompile testing")
hjm_decode("哈基米哈基米")
sk, pk = hjm_generate_ed_keys()
hjm_sign("test", sk)
hjm_verify("test", "sig", pk)
hjm_dh_generate_keys(save=false)
