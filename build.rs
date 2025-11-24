use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to watch for XEN_PUBLIC variable
    println!("cargo::rerun-if-env-changed=XEN_PUBLIC");

    let headers = [
        "event_channel.h",
        "sysctl.h",
        "hypfs.h",
        "domctl.h",
        "hvm/hvm_op.h",
        "hvm/dm_op.h",
        "xen.h",
    ];
    // Check if user provided path for xen public headers
    let xen_public_env = env::var("XEN_PUBLIC");
    let xen_public_s = xen_public_env.unwrap_or_else(|_| {
	println!("cargo::warning=XEN_PUBLIC environment variable is not specified. Defaulting to 'target/xen/xen/include/public/'");
	"target/xen/xen/include/public/".to_string()
    });

    let xen_public = PathBuf::from(xen_public_s)
        .canonicalize()
        .expect("Can't canonicalize path to xen public includes");

    // Generate absolute path to headers
    let headers = headers.map(|x| {
        let mut h = xen_public.clone();
        h.push(x);
        h.display().to_string()
    });

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .headers(headers)
        .clang_arg("--target=aarch64")
        .clang_arg("-D__XEN_TOOLS__")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
