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
        .current_dir("enigma-kms-node")
        .arg("build")
        .output()
        .expect("Failed to build submodule");
    println!("✅ Build Submodule Completed!");
    println!("✅ Build Completed!");
}
