use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/main.rs");

    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let qemu_dir = format!("{}/qemu", cwd);

    // clean doesn't know about the install directory we use to build, remove it as well
    Command::new("rm")
        .arg("-r")
        .arg("-v")
        .arg("-f")
        .arg(&format!("{}/build", qemu_dir))
        .arg(&format!("{}/_install", qemu_dir))
        .current_dir(qemu_dir.clone())
        .status()
        .expect("Couldn't clean qemu's build directory");

    // create the build & install directories
    Command::new("mkdir")
        .arg("-p")
        .arg("build")
        .arg("_install")
        .current_dir(qemu_dir.clone())
        .status()
        .expect("Couldn't create qemu's build directory");

    // configure with afl-clang-fast and set install directory to ./qemu/_install
    Command::new("../configure")
        .arg(&format!("--prefix={}/_install", qemu_dir))
        .arg("--target-list=aarch64-softmmu")
        .env("CC", "/usr/local/bin/afl-clang-fast")
        .env("CXX", "/usr/local/bin/afl-clang-fast++")
        .current_dir(qemu_dir.clone() + "/build")
        .status()
        .expect("Couldn't configure qemu to build using afl-clang-fast");

    // make
    Command::new("make")
        .arg("-j12")
        .current_dir(qemu_dir.clone() + "/build")
        .status()
        .expect("Couldn't make qemu");

    // install
    Command::new("make")
        .arg("install")
        .arg("-j12")
        .current_dir(qemu_dir.clone() + "/build")
        .status()
        .expect("Couldn't install qemu");
}
