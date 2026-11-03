//! Compiles the zkEVM guest for the SP1 RISC-V target.
//!
//! The guest is this same crate: its library target (`src/lib.rs`) is the
//! program the zkVM runs. `sp1-build` invokes `cargo prove build` on this
//! package, which cross-compiles the binaries of the package for the
//! `riscv32im-succinct-zkvm-elf` target and drops the result in
//! `<target-dir>/elf-compilation/...`. It then exports the path to this crate's
//! build script as `SP1_ELF_zethora-prover`, which is what `include_elf!` in
//! `src/main.rs` embeds into the host binary.
//!
//! The build is skipped when `SP1_SKIP_PROGRAM_BUILD=true` is set, which is how
//! you build the host on a machine without the SP1 toolchain (or without
//! caching the toolchain first) when you will not be proving locally.

fn main() {
    // Include the dependencies of the guest in the rebuild fingerprint, so
    // changing the EVM (or the raw transaction codec it uses) rebuilds the ELF
    // instead of silently proving with a stale one.
    println!("cargo:rerun-if-changed=../zethora-evm/src");
    println!("cargo:rerun-if-changed=../zethora-evm/Cargo.toml");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/sample_batch.rs");

    sp1_build::build_program(".");
}
