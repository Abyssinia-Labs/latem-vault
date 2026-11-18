//! `latem-vault join` and `latem-vault approve` (join.md, commands).
//!
//! The joiner runs its own endpoint, because it has no vault for a service to hold yet. `approve`
//! goes through the service when one runs (service.md, for apps), and otherwise runs its own
//! endpoint and opens the vault itself.

use std::io::{self, BufRead, IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use latem_vault_core::membership::{AdminKey as _, DeviceName, Scope};
use latem_vault_core::{CollectionId, Vault, transport_seed};
use latem_vault_crypto::pake;
use latem_vault_keystore::{AdminKey, Backend, Keys};
use latem_vault_net::join::{self, AdminSession, JoinError};
use latem_vault_net::{EndpointKey, Node, Options};
use tokio::runtime::Runtime;
use tokio::time::Instant;

use latem_vault_service::handler;
use latem_vault_service::setup::{self, ATTEMPTS, JoinProgress};

use crate::{Home, load_keys, read_new_passphrase, read_recovery_phrase};

/// How long `approve` looks for joining devices.
const LOOK_TIME: Duration = Duration::from_secs(15);

pub fn join(home: &Home, backend: Backend, name: String) -> Result<()> {
    let name = DeviceName {
        platform: std::env::consts::OS.into(),
        name,
    };
    name.check()?;
    let (keys, device) = setup::joining_keys(&home.0, backend, read_new_passphrase, load_keys)?;
    let code = pake::new_code();

    println!("Joining as {} ({}).", name.name, name.platform);
    println!();
    println!(
        "On a device that administers the vault, run `latem-vault approve` and enter this code:"
    );
    println!();
    println!("    {} {}", &code[..3], &code[3..]);
    println!();
    println!("Waiting up to 10 minutes. Ctrl-C cancels.");

    let progress = |progress| match progress {
        JoinProgress::WrongCode { .. } => eprintln!("A device tried a wrong code."),
        JoinProgress::Failed(error) => eprintln!("A join attempt failed: {error}"),
        JoinProgress::CodeAccepted => {
            println!("Code accepted. Waiting for the admin to approve this device...");
        }
    };
    let joined = runtime()?.block_on(setup::join(
        &home.0,
        keys,
        device,
        &name,
        &code,
        progress,
        std::future::pending(),
    ));
    let vault = joined.context("run `latem-vault join` again for a new code")?;
    println!();
    println!("Joined the vault {} as {}.", vault.vault_id(), name.name);
    println!();
    println!("{}", crate::START_THE_SERVICE);
    Ok(())
}

pub fn approve(home: &Home, write: &[String], read: &[String], hold: &[String]) -> Result<()> {
    home.require_vault()?;
    #[cfg(unix)]
    {
        let socket = home.0.join(latem_vault_service::SOCKET);
        if latem_vault_service::client::is_running(&socket) {
            return approve_through_service(&socket, write, read, hold);
        }
    }
    let keys = load_keys(&home.keys())?;
    let seed = transport_seed(&keys);
    let mut vault = Vault::open(&home.vault(), keys)?;
    if vault.membership().is_none() {
        bail!("this vault has no membership log yet; creating a collection starts it");
    }
    let scopes = scopes(&vault, write, read, hold)?;

    let runtime = runtime()?;
    let options = Options {
        advertise: false,
        ..Options::default()
    };
    let (node, _events) = runtime.block_on(Node::start(&seed, options))?;
    drop(seed);
    let result = approve_with(home, &runtime, &node, &mut vault, &scopes);
    runtime.block_on(node.close());
    result
}

fn approve_with(
    home: &Home,
    runtime: &Runtime,
    node: &Node,
    vault: &mut Vault<Keys>,
    scopes: &[(CollectionId, Scope, String)],
) -> Result<()> {
    let (joiner, hint) = pick_joiner(runtime, node)?;
    let mut attempts = 0;
    let session = loop {
        let code = read_code(&hint)?;
        match runtime.block_on(AdminSession::start(node.endpoint(), joiner, &code)) {
            Ok(session) => break session,
            Err(JoinError::WrongCode) => {
                attempts += 1;
                if attempts == ATTEMPTS {
                    bail!(
                        "three wrong codes; run `latem-vault join` and `latem-vault approve` again"
                    );
                }
                eprintln!("Wrong code.");
            }
            Err(error) => return Err(error.into()),
        }
    };

    let request = session.request().clone();
    let scope_list = if scopes.is_empty() {
        "none".to_owned()
    } else {
        scopes
            .iter()
            .map(|(_, scope, name)| format!("{} {name}", scope_label(*scope)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let id = request.device.to_string();
    println!();
    println!("Device    {}", request.name.name);
    println!("Platform  {}", request.name.platform);
    println!(
        "Keys      {}",
        if request.is_hardware() {
            "hardware"
        } else {
            "file"
        }
    );
    println!("Id        {}…", &id[..8]);
    println!("Scopes    {scope_list}");
    println!();
    if !confirm("Approve this device? [y/N] ")? {
        runtime.block_on(session.refuse("not approved"));
        bail!("not approved");
    }

    let named: Vec<(String, Scope)> = scopes
        .iter()
        .map(|(_, scope, name)| (name.clone(), *scope))
        .collect();
    if listed_admin_key(home, vault)?.is_some() {
        eprintln!(
            "Confirm with Touch ID or your password to add {} to your vault.",
            request.name.name
        );
    }
    let approval = match handler::approve_join(vault, &home.admin(), None, &request, &named, None) {
        Err(error) if handler::needs_recovery_phrase(&error) => {
            recovery_phrase_note();
            let phrase = read_recovery_phrase()?;
            handler::approve_join(vault, &home.admin(), None, &request, &named, Some(&phrase))
        }
        approval => approval,
    };
    let approval = match approval {
        Ok(approval) => approval,
        Err(error) => {
            runtime.block_on(session.refuse(&error.to_string()));
            return Err(error);
        }
    };
    runtime.block_on(session.finish(vault.vault_id(), &approval.log, &approval.grants))?;
    println!(
        "{} joined the vault, with scopes {scope_list}.",
        request.name.name
    );
    // A running service reloads the log and tells the other devices (service.md, the store).
    #[cfg(unix)]
    let _ = latem_vault_service::client::call(
        &home.0.join(latem_vault_service::SOCKET),
        &latem_vault_service::api::Request::Changed,
    );
    Ok(())
}

/// `approve` with the service's endpoint (service.md, for apps): the same steps, each a request.
#[cfg(unix)]
fn approve_through_service(
    socket: &std::path::Path,
    write: &[String],
    read: &[String],
    hold: &[String],
) -> Result<()> {
    use latem_vault_service::api::{ErrorCode, Request, Response};

    let call = |request: &Request| -> Result<Response> {
        latem_vault_service::client::call(socket, request)?
            .ok_or_else(|| anyhow!("the service stopped; run `latem-vault approve` again"))
    };
    let mut scopes: Vec<(String, Scope)> = Vec::new();
    for (names, scope) in [
        (write, Scope::Write),
        (read, Scope::Read),
        (hold, Scope::Hold),
    ] {
        for name in names {
            if scopes.iter().any(|(other, _)| other == name) {
                bail!("{name} is given more than one scope");
            }
            scopes.push((name.clone(), scope));
        }
    }

    eprintln!("Looking for devices waiting to join on this network...");
    let start = Instant::now();
    let mut first_found: Option<Instant> = None;
    let joiners = loop {
        let joiners = match call(&Request::Joiners)? {
            Response::Joiners(joiners) => joiners,
            other => return Err(handler::unexpected(&other)),
        };
        if !joiners.is_empty() && first_found.is_none() {
            first_found = Some(Instant::now());
        }
        // Once one is found, a little longer, in case others are about to appear.
        let settled = first_found.is_some_and(|at| at.elapsed() > Duration::from_secs(2));
        if settled || start.elapsed() > LOOK_TIME {
            break joiners;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let joiner = match joiners.as_slice() {
        [] => {
            bail!(
                "no device on this network is waiting to join; run `latem-vault join` on it first"
            )
        }
        [joiner] => {
            eprintln!("Found {} ({}).", joiner.name, joiner.platform);
            joiner
        }
        several => {
            for (i, joiner) in several.iter().enumerate() {
                eprintln!("{:>3}. {} ({})", i + 1, joiner.name, joiner.platform);
            }
            let choice = prompt(&format!("Which device? [1-{}] ", several.len()))?;
            let index: usize = choice.trim().parse().context("not a number")?;
            several
                .get(index.wrapping_sub(1))
                .ok_or_else(|| anyhow!("there is no device {index}"))?
        }
    };

    let request = loop {
        let code = zeroize::Zeroizing::new(read_code(&joiner.name)?);
        match call(&Request::CheckCode {
            joiner: joiner.endpoint,
            code,
        })? {
            Response::JoinRequest(request) => break request,
            Response::Error {
                code: ErrorCode::WrongCode,
                message,
            } => eprintln!("{}.", capitalized(&message)),
            other => return Err(handler::unexpected(&other)),
        }
    };

    let scope_list = if scopes.is_empty() {
        "none".to_owned()
    } else {
        scopes
            .iter()
            .map(|(name, scope)| format!("{} {name}", scope_label(*scope)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let id = request.device.to_string();
    println!();
    println!("Device    {}", request.name);
    println!("Platform  {}", request.platform);
    println!(
        "Keys      {}",
        if request.hardware { "hardware" } else { "file" }
    );
    println!("Id        {}…", &id[..8]);
    println!("Scopes    {scope_list}");
    println!();
    if !confirm("Approve this device? [y/N] ")? {
        call(&Request::Refuse {
            session: request.session,
        })?;
        bail!("not approved");
    }

    eprintln!("Confirm with Touch ID or your password if asked.");
    let mut recovery_phrase = None;
    loop {
        match call(&Request::Approve {
            session: request.session,
            scopes: scopes.clone(),
            recovery_phrase: recovery_phrase.take(),
        })? {
            Response::Done => break,
            Response::Error {
                code: ErrorCode::RecoveryPhraseNeeded,
                ..
            } => {
                recovery_phrase_note();
                recovery_phrase = Some(read_recovery_phrase()?);
            }
            other => return Err(handler::unexpected(&other)),
        }
    }
    println!(
        "{} joined the vault, with scopes {scope_list}.",
        request.name
    );
    Ok(())
}

fn recovery_phrase_note() {
    if io::stdin().is_terminal() {
        eprintln!("Approving needs an admin signature. This device has no admin key, so");
        eprintln!("it comes from your recovery phrase.");
    }
}

fn capitalized(message: &str) -> String {
    let mut chars = message.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Finds the devices waiting to join on this network, and picks one.
fn pick_joiner(runtime: &Runtime, node: &Node) -> Result<(EndpointKey, String)> {
    eprintln!("Looking for devices waiting to join on this network...");
    let joiners = runtime.block_on(async {
        let start = Instant::now();
        let mut first_found: Option<Instant> = None;
        loop {
            let joiners: Vec<(EndpointKey, (String, String))> = node
                .announcements()
                .into_iter()
                .filter_map(|(key, announcement)| {
                    Some((key, join::parse_announcement(&announcement)?))
                })
                .collect();
            if !joiners.is_empty() && first_found.is_none() {
                first_found = Some(Instant::now());
            }
            // Once one is found, a little longer, in case others are about to appear.
            let settled = first_found.is_some_and(|at| at.elapsed() > Duration::from_secs(2));
            if settled || start.elapsed() > LOOK_TIME {
                break joiners;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });
    let label = |(platform, name): &(String, String)| format!("{name} ({platform})");
    match joiners.as_slice() {
        [] => {
            bail!(
                "no device on this network is waiting to join; run `latem-vault join` on it first"
            )
        }
        [(key, hint)] => {
            eprintln!("Found {}.", label(hint));
            Ok((*key, hint.1.clone()))
        }
        several => {
            for (i, (_, hint)) in several.iter().enumerate() {
                eprintln!("{:>3}. {}", i + 1, label(hint));
            }
            let choice = prompt(&format!("Which device? [1-{}] ", several.len()))?;
            let index: usize = choice.trim().parse().context("not a number")?;
            let (key, hint) = several
                .get(index.wrapping_sub(1))
                .ok_or_else(|| anyhow!("there is no device {index}"))?;
            Ok((*key, hint.1.clone()))
        }
    }
}

/// The collections and scopes from `approve`'s flags.
fn scopes(
    vault: &Vault<Keys>,
    write: &[String],
    read: &[String],
    hold: &[String],
) -> Result<Vec<(CollectionId, Scope, String)>> {
    let mut scopes: Vec<(CollectionId, Scope, String)> = Vec::new();
    for (names, scope) in [
        (write, Scope::Write),
        (read, Scope::Read),
        (hold, Scope::Hold),
    ] {
        for name in names {
            let id = vault.collection(name)?;
            if scopes.iter().any(|(other, ..)| *other == id) {
                bail!("{name} is given more than one scope");
            }
            scopes.push((id, scope, name.clone()));
        }
    }
    Ok(scopes)
}

/// This device's admin key, if it has one and the vault lists it as an admin.
fn listed_admin_key(home: &Home, vault: &Vault<Keys>) -> Result<Option<AdminKey>> {
    let key = match AdminKey::load(&home.admin()) {
        Ok(key) => key,
        Err(latem_vault_keystore::Error::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let listed = vault
        .membership()
        .is_some_and(|m| m.admins().contains(&key.verifying_key()));
    Ok(listed.then_some(key))
}

fn read_code(device: &str) -> Result<String> {
    let code: String = prompt(&format!("Code shown on {device}: "))?
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        bail!("the code is six digits, such as 123 456");
    }
    Ok(code)
}

pub(crate) fn confirm(question: &str) -> Result<bool> {
    let answer = prompt(question)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Asks on stderr and reads a line from stdin.
fn prompt(question: &str) -> Result<String> {
    eprint!("{question}");
    io::stderr().flush()?;
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("no answer: stdin is closed");
    }
    Ok(line)
}

pub(crate) fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::Write => "write",
        Scope::Read => "read",
        Scope::Hold => "hold",
        Scope::None => "none",
    }
}

fn runtime() -> Result<Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}
