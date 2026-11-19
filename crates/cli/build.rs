//! Records the commit this binary is built from, for `--version` and the service's start line
//! (README, versions). Without git or outside a checkout, the commit is "unknown".

use std::path::Path;
use std::process::Command;

fn main() {
    let commit = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=PINKVAULT_COMMIT={commit}");

    // Run again when HEAD moves: switching branches rewrites HEAD, and a commit rewrites the
    // branch it names, or packed-refs once refs are packed.
    let mut watched = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    watched.extend(git(&["symbolic-ref", "-q", "HEAD"]));
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo");
    for name in watched {
        if let Some(path) = git(&["rev-parse", "--git-path", &name]) {
            let path = Path::new(&manifest).join(path);
            // A path that doesn't exist would make cargo run this script on every build.
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

/// The trimmed output of a git command, or `None` if it didn't run or failed.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (output.status.success() && !text.is_empty()).then(|| text.to_owned())
}
