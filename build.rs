fn main() {
    println!("cargo:rustc-link-lib=dylib=bcrypt");
    println!("cargo:rustc-link-lib=dylib=ncrypt");
    println!("cargo:rustc-link-lib=dylib=crypt32");
}