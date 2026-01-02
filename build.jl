# build.jl
using Pkg

println("--- [Hajimi] Activating & Instantiating ---")
Pkg.activate(".")

try
    Pkg.resolve()
    Pkg.instantiate()
catch e
    println("\n[!] Standard instantiation failed. This is typical for Julia 1.12 stdlibs.")
    println("[!] Attempting to repair by re-adding local stubs...")
    Pkg.add(["Random", "Serialization", "SHA"])
end

using PackageCompiler

println("--- [Hajimi] Starting Compilation ---")
create_app(".", "HajimiApp",
    force=true,
    executables=["hjm" => "julia_main"],
    precompile_execution_file="src/precompile.jl",
    incremental=false,
    filter_stdlibs=true
)

println("\n--- [Hajimi] Build Success! ---")