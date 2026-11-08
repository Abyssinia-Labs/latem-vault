//! `openvault join` and `openvault approve` (join.md, commands).
//!
//! Both run their own endpoint, the joiner because it has no vault for a service to hold yet,
//! and `approve` because it needs the user at every step. `approve` opens the vault itself even
//! while the service runs; the service picks up the new log entries on its next request.

use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use openvault_core::membership::{AdminKey as _, DeviceName, Scope};
use openvault_core::{CollectionId, DeviceId, Vault, transport_seed};
use openvault_crypto::RecoveryKey;
use openvault_crypto::pake;
use openvault_keystore::{AdminKey, Backend, Keys};
use openvault_net::join::{self, AdminSession, JoinError, JoinerSession};
use openvault_net::{EndpointKey, Node, Options};
use tokio::runtime::Runtime;
use tokio::time::Instant;

use crate::{Home, create_private_dir, load_keys, read_new_passphrase, read_recovery_phrase};

/// The file that holds a joining device's id until the join completes, so running `join` again
/// resumes with the same identity (join.md, commands).
const JOINING: &str = "joining";
/// How long a code is shown for (join.md, the code).
const JOIN_TIME: Duration = Duration::from_secs(10 * 60);
/// Failed PAKE sessions before the joiner, or `approve`, gives up.
const ATTEMPTS: usize = 3;
/// How long `approve` looks for joining devices.
const LOOK_TIME: Duration = Duration::from_secs(15);

pub fn join(home: &Home, backend: Backend, name: String) -> Result<()> {
    if home.vault().exists() {
        bail!("this device is already in a vault ({})", home.0.display());
    }
    let name = DeviceName {
        platform: std::env::consts::OS.into(),
        name,
    };
    name.check()?;
    let (keys, device) = joining_keys(home, backend)?;
    let code = pake::new_code();

    println!("Joining as {} ({}).", name.name, name.platform);
    println!();
    println!(
        "On a device that administers the vault, run `openvault approve` and enter this code:"
    );
    println!();
    println!("    {} {}", &code[..3], &code[3..]);
    println!();
    println!("Waiting up to 10 minutes. Ctrl-C cancels.");

    let runtime = runtime()?;
    let vault = runtime.block_on(async {
        let options = Options {
            alpns: vec![join::ALPN.to_vec()],
            announcement: Some(join::announcement(&name)),
            ..Options::default()
        };
        let (node, _events) = Node::start(&transport_seed(&keys), options).await?;
        let result = accept_join(home, &node, keys, device, &name, &code).await;
        node.close().await;
        result
    })?;
    let _ = fs::remove_file(home.0.join(JOINING));
    println!();
    println!("Joined the vault {} as {}.", vault.vault_id(), name.name);
    Ok(())
}

/// The keys and id of a join in progress, or new ones.
fn joining_keys(home: &Home, backend: Backend) -> Result<(Keys, DeviceId)> {
    let joining = home.0.join(JOINING);
    if home.keys().exists() {
        let id = fs::read_to_string(&joining).with_context(|| {
            format!(
                "{} has a key file but no vault and no join in progress",
                home.0.display()
            )
        })?;
        let device = id.trim().parse().context("the joining file is damaged")?;
        return Ok((load_keys(&home.keys())?, device));
    }
    let passphrase = match backend {
        Backend::Passphrase => Some(read_new_passphrase()?),
        _ => None,
    };
    create_private_dir(&home.0)?;
    let keys = match &passphrase {
        Some(passphrase) => Keys::create_with_passphrase(&home.keys(), passphrase)?,
        None => Keys::create(&home.keys(), backend)?,
    };
    let device = DeviceId::random();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
        .open(&joining)
        .and_then(|mut file| writeln!(file, "{device}"));
    if let Err(e) = written {
        let _ = fs::remove_file(home.keys());
        return Err(e).context("can't save the joining device's id");
    }
    Ok((keys, device))
}

/// Answers admins until one completes the join, three sessions fail, or the time is up.
async fn accept_join(
    home: &Home,
    node: &Node,
    keys: Keys,
    device: DeviceId,
    name: &DeviceName,
    code: &str,
) -> Result<Vault<Keys>> {
    let deadline = Instant::now() + JOIN_TIME;
    let mut failures = 0;
    loop {
        let incoming = tokio::select! {
            incoming = node.endpoint().accept() => incoming.context("the endpoint closed")?,
            _ = tokio::time::sleep_until(deadline) => {
                bail!("no admin approved this device within 10 minutes; run `openvault join` again");
            }
        };
        let Ok(connection) = incoming.await else {
            continue;
        };
        let mut session = match JoinerSession::accept(connection, node.id(), code).await {
            Ok(session) => session,
            Err(error) => {
                failures += 1;
                match error {
                    JoinError::WrongCode => eprintln!("A device tried a wrong code."),
                    other => eprintln!("A join attempt failed: {other}"),
                }
                if failures == ATTEMPTS {
                    bail!("three join attempts failed; run `openvault join` again for a new code");
                }
                continue;
            }
        };
        println!("Code accepted. Waiting for the admin to approve this device...");
        let request = openvault_core::join::JoinRequest::sign(
            session.session_id(),
            device,
            &keys,
            name.clone(),
        )?;
        let accepted = session.request(&request, deadline).await?;
        let (log, grants) = session.receive(accepted.head).await?;
        return match Vault::join(
            &home.vault(),
            keys,
            device,
            name,
            accepted.head,
            &log,
            &grants,
        ) {
            Ok(vault) if vault.vault_id() == accepted.vault => {
                session.joined().await?;
                Ok(vault)
            }
            Ok(_) => {
                let _ = fs::remove_file(home.vault());
                session.fail("the log is another vault's").await;
                bail!("the admin sent another vault's log")
            }
            Err(error) => {
                session.fail(&error.to_string()).await;
                Err(anyhow!(error).context("the admin's vault didn't check out"))
            }
        };
    }
}

pub fn approve(home: &Home, write: &[String], read: &[String], hold: &[String]) -> Result<()> {
    home.require_vault()?;
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
                    bail!("three wrong codes; run `openvault join` and `openvault approve` again");
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

    let collections: Vec<(CollectionId, Scope)> =
        scopes.iter().map(|(id, scope, _)| (*id, *scope)).collect();
    let approval = match listed_admin_key(home, vault)? {
        Some(admin) => {
            let reason = format!("add {} to your vault", request.name.name);
            eprintln!("Confirm with Touch ID or your password to {reason}.");
            vault.approve_join(&request, &collections, &admin.with_reason(reason))
        }
        None => {
            if io::stdin().is_terminal() {
                eprintln!("Approving needs an admin signature. This device has no admin key, so");
                eprintln!("it comes from your recovery phrase.");
            }
            let recovery = RecoveryKey::from_phrase(&read_recovery_phrase()?)?;
            if !vault.is_recovery_key(&recovery) {
                runtime.block_on(session.refuse("not approved"));
                bail!("that recovery phrase belongs to another vault");
            }
            vault.approve_join(&request, &collections, &recovery.admin_signing_key())
        }
    };
    let approval = match approval {
        Ok(approval) => approval,
        Err(error) => {
            runtime.block_on(session.refuse(&error.to_string()));
            return Err(error.into());
        }
    };
    runtime.block_on(session.finish(vault.vault_id(), &approval.log, &approval.grants))?;
    println!(
        "{} joined the vault, with scopes {scope_list}.",
        request.name.name
    );
    Ok(())
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
            bail!("no device on this network is waiting to join; run `openvault join` on it first")
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
        Err(openvault_keystore::Error::NotFound(_)) => return Ok(None),
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

fn confirm(question: &str) -> Result<bool> {
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

fn scope_label(scope: Scope) -> &'static str {
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
