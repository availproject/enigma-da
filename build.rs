use std::process::Command;

fn main() {
    println!("🚀 Build Initiated!");
    let _ = Command::new("git")
        .arg("submodule")
        .arg("update")
        .arg("--init")
        .output()
        .expect("Failed to fetch submodule");
    println!("✅ Fetch Submodule Completed!");
    let _ = Command::new("cargo")
        .current_dir("../enigma-kms-node")
        .arg("build")
        .arg("--features")
        .arg("persistent-connection")
        .output()
        .expect("Failed to build submodule");
    println!("✅ Build Submodule Completed!");
    let _ = Command::new("cp")
        .arg("../enigma-kms-node/target/debug/enigma-kms-node")
        .arg("../target/debug/enigma-kms-node")
        .output()
        .expect("Failed to copy binary");
    println!("✅ Copy Binary Completed!");
    println!("✅ Build Completed!");
}
