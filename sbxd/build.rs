//! Builds the eBPF object in `../sbxd-ebpf` for the BPF target and copies it
//! next to the daemon so `ebpf.rs` can embed it with `include_bytes!`.
//!
//! The eBPF crate is its own workspace and only builds for
//! `bpfel-unknown-none`, which needs nightly with `rust-src` plus
//! `bpf-linker`; neither can be expressed in a Cargo dependency.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let ebpf = manifest
        .parent()
        .expect("sbxd lives inside the workspace")
        .join("sbxd-ebpf");
    println!("cargo:rerun-if-changed={}", ebpf.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf.join("Cargo.toml").display()
    );

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let target = out.join("bpf-target");
    // `CARGO` is the real cargo binary here, not the rustup shim, so the
    // toolchain is selected through `rustup` explicitly.
    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--manifest-path",
        ])
        .arg(ebpf.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", &target)
        // The outer cargo exports RUSTC/RUSTDOC pointing at the stable
        // toolchain it was invoked with; the nested build must not inherit
        // them or `-Z build-std` looks for rust-src in the wrong toolchain.
        .env("RUSTUP_TOOLCHAIN", "nightly")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .status()
        .expect("failed to start cargo for sbxd-ebpf");
    assert!(status.success(), "sbxd-ebpf failed to build");

    let object = target.join("bpfel-unknown-none/release/libsbxd_ebpf.so");
    fs::copy(&object, out.join("sbxd-ebpf.o"))
        .unwrap_or_else(|e| panic!("copy {}: {e}", object.display()));
}
