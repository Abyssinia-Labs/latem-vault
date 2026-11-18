//! `latem-vault keys` and `latem-vault keys passphrase [--remove]` (keystore.md, changing the
//! protection).

use anyhow::{Result, bail};
use latem_vault_keystore::{Backend, Keys};
use zeroize::Zeroizing;

use crate::join::confirm;
#[cfg(unix)]
use crate::login;
use crate::{Home, has_terminal, prompt_passphrase, read_new_passphrase};

/// Says how this device's keys are kept, without opening them.
pub fn show(home: &Home) -> Result<()> {
    let path = home.keys();
    let backend = latem_vault_keystore::backend_of(&path)?;
    println!("{}", path.display());
    println!(
        "{}",
        match backend {
            Backend::SecureEnclave =>
                "In the Secure Enclave: they can't be copied off this Mac, and they open with \
                 nobody there.",
            Backend::Passphrase =>
                "In a key file protected by a passphrase: a copy of the file needs the passphrase \
                 too. A service the system starts can't type it, so `latem-vault service install` \
                 refuses these keys.",
            Backend::Software =>
                "In a key file protected only by its permissions: whoever can read it as you, or \
                 copies it, has the keys. They open with nobody there, so the service can start \
                 at login.",
        }
    );
    Ok(())
}

/// Gives the key file a passphrase, or changes the one it has.
pub fn set_passphrase(home: &Home) -> Result<()> {
    let path = home.keys();
    let backend = latem_vault_keystore::backend_of(&path)?;
    if backend == Backend::SecureEnclave {
        return Err(latem_vault_keystore::Error::InSecureEnclave.into());
    }
    require_terminal()?;
    let current = match backend {
        Backend::Passphrase => Some(current_passphrase(home)?),
        _ => None,
    };
    let new = read_new_passphrase()?;
    Keys::change_passphrase(&path, current.as_deref().map(String::as_str), Some(&new))?;
    if current.is_some() {
        println!("The passphrase is changed. The device's keys are the same.");
    } else {
        println!(
            "This device's keys are now protected by a passphrase. Copies of the key file made \
             before now, in a backup for instance, still open without one."
        );
        #[cfg(unix)]
        if login::installed() {
            println!(
                "The service is installed to start at login, and can't type a passphrase, so it \
                 won't start again by itself. `latem-vault service uninstall` takes it away."
            );
        }
    }
    Ok(())
}

/// Takes the key file's passphrase away, after saying what that means and asking.
pub fn remove_passphrase(home: &Home) -> Result<()> {
    let path = home.keys();
    match latem_vault_keystore::backend_of(&path)? {
        Backend::SecureEnclave => return Err(latem_vault_keystore::Error::InSecureEnclave.into()),
        Backend::Software => bail!("this device's key file has no passphrase"),
        Backend::Passphrase => {}
    }
    require_terminal()?;
    eprintln!(
        "Without a passphrase, the key file is protected only by its permissions: whoever can \
         read it as you, or copies it, has this device's keys. In exchange, they open with nobody \
         there, so `latem-vault service install` can start the service at login."
    );
    if !confirm("Remove the passphrase? [y/N] ")? {
        bail!("not removed");
    }
    let current = current_passphrase(home)?;
    Keys::change_passphrase(&path, Some(&current), None)?;
    println!(
        "The passphrase is removed. The device's keys are the same, and `latem-vault service \
         install` can now start the service at login."
    );
    Ok(())
}

fn require_terminal() -> Result<()> {
    if !has_terminal() {
        bail!("there's no terminal to type a passphrase in");
    }
    Ok(())
}

/// Asks for the key file's passphrase until it opens the keys, three times at most.
fn current_passphrase(home: &Home) -> Result<Zeroizing<String>> {
    const ATTEMPTS: usize = 3;
    for attempt in 1..=ATTEMPTS {
        let passphrase = prompt_passphrase("Current passphrase for this device's keys (hidden): ")?;
        match Keys::load_with_passphrase(&home.keys(), &passphrase) {
            Ok(_) => return Ok(passphrase),
            Err(latem_vault_keystore::Error::WrongPassphrase) if attempt < ATTEMPTS => {
                eprintln!("Wrong passphrase.");
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!("the last attempt returns")
}
