use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=src-media/logo.ico");
    println!("cargo:rerun-if-env-changed=RC");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }

    let compiler = env::var_os("RC")
        .map(PathBuf::from)
        .or_else(|| {
            let sdk = PathBuf::from(env::var_os("ProgramFiles(x86)")?).join("Windows Kits/10/bin");
            let mut versions: Vec<_> = fs::read_dir(sdk)
                .ok()?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("10."))
                })
                .collect();
            versions.sort();
            versions
                .into_iter()
                .rev()
                .map(|p| p.join("x64/rc.exe"))
                .find(|p| p.is_file())
        })
        .unwrap_or_else(|| PathBuf::from("rc.exe"));
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let numeric_version = format!(
        "{},{},{},0",
        env::var("CARGO_PKG_VERSION_MAJOR").unwrap(),
        env::var("CARGO_PKG_VERSION_MINOR").unwrap(),
        env::var("CARGO_PKG_VERSION_PATCH").unwrap()
    );
    let source = fs::read_to_string("app.rc")
        .expect("read Windows resource template")
        .replace("@VERSION_NUMBER@", &numeric_version)
        .replace("@VERSION@", &version);
    let resource_source = output.join("app.rc");
    fs::write(&resource_source, source).expect("write Windows resource");
    let resource = output.join("app.res");
    let status = Command::new(compiler)
        .current_dir(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource)
        .arg(&resource_source)
        .status()
        .expect("Windows SDK resource compiler is required to embed the application icon");
    assert!(status.success(), "application resource compilation failed");
    println!(
        "cargo:rustc-link-arg-bin=no-router-mercy={}",
        resource.display()
    );
}
