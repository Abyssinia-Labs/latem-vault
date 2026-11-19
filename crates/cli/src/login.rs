//! `pinkvault service install | uninstall | status`: having the operating system start the
//! service at login (service.md, starting at login). A LaunchAgent on macOS and a systemd user
//! unit on Linux, each running `pinkvault service` from this binary.
//!
//! Before 0.7 they had latem vault's names, and before 0.6 openvault's ([`OLD_LABELS`],
//! [`OLD_UNITS`]). `install` and `uninstall` remove those definitions too, so two don't start two
//! services for one vault.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use pinkvault_keystore::Backend;
use pinkvault_service::SOCKET;
use pinkvault_service::api::{Request, Response};
use pinkvault_service::home::{self, HOME_VAR, Location, OLD_HOME_VARS};

#[cfg_attr(not(target_os = "macos"), allow(unused_imports))]
use crate::migrate::OLD_LABELS;
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use crate::migrate::OLD_UNITS;
use crate::migrate::{self, OLD_APP_LABELS};
use crate::{Home, VERSION};

/// The LaunchAgent's label, which also names its file.
const LABEL: &str = "com.abyssinialabs.pinkvault.service";
/// The Mac app's own LaunchAgent, which starts the bundled binary instead (service.md, the Mac
/// app), once the app has PinkVault's name (OV-12). Until then it's one of [`OLD_APP_LABELS`].
/// It has `install`'s label, so launchd runs only one of the two, and where its definition is
/// says which ([`SystemState::path`]).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const APP_LABEL: &str = LABEL;
/// How long `install` waits for the new service to answer.
const STARTING: Duration = Duration::from_secs(10);

/// What a definition runs: `pinkvault service` from `exe`, with `PINKVAULT_HOME` set to
/// `home` when it, or an old name for it, was set for `install`.
struct Definition {
    exe: String,
    home: Option<String>,
}

pub fn install() -> Result<()> {
    if app_state()?.is_some() {
        bail!(
            "the Mac app starts the service on this Mac, with its own copy of pinkvault. To \
             have this binary start it instead, turn the app off in System Settings > General > \
             Login Items first"
        );
    }
    // Checked on the directory as it is, before anything is stopped or moved.
    let current = Home(Location::from_env()?.current());
    current.require_vault()?;
    if pinkvault_keystore::backend_of(&current.keys())? == Backend::Passphrase {
        bail!(
            "this device's keys are protected by a passphrase, and a service the system starts \
             has nobody to type it. Either remove the passphrase with `pinkvault keys \
             passphrase --remove`, or start `pinkvault service` by hand after each restart"
        );
    }
    let definition = Definition::for_this_binary()?;
    if definition.exe.contains("/target/debug/") || definition.exe.contains("/target/release/") {
        eprintln!(
            "Warning: {} is in a cargo target directory, which each build replaces. \
             `cargo install --path crates/cli` puts pinkvault somewhere that lasts.",
            definition.exe
        );
    }

    // The services with the old names stop here, so the vault can move and only this one
    // starts it.
    remove_old()?;
    let home = Home(migrate::locate()?);

    let socket = home.0.join(SOCKET);
    let running = system_state()?;
    let before = call_status(&socket);
    if before.is_some() && !running.running {
        bail!(
            "a service the system didn't start is already running for this vault, in a \
             terminal for instance. Stop it first, then run this again"
        );
    }
    let old_pid = match before {
        Some(Response::Status { pid, .. }) => Some(pid),
        _ => running.pid,
    };

    let path = definition_path()?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("can't create {}", dir.display()))?;
    }
    let contents = render(&definition)?;
    let staged = path.with_extension("new");
    fs::write(&staged, contents).with_context(|| format!("can't write {}", staged.display()))?;
    fs::rename(&staged, &path).with_context(|| format!("can't write {}", path.display()))?;
    println!("Wrote {}", path.display());
    start(&path)?;

    match wait_for_new_service(&socket, old_pid) {
        Some((version, pid)) => {
            println!("The service is running: pinkvault {version}, pid {pid}.")
        }
        None => println!(
            "The service didn't answer within {} seconds. {}",
            STARTING.as_secs(),
            where_it_logs()
        ),
    }
    after_install()?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let path = definition_path()?;
    stop()?;
    let removed_old = remove_old()?;
    match fs::remove_file(&path) {
        Ok(()) => println!("Removed {}. The vault is untouched.", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match app_state()? {
            _ if removed_old => {}
            Some(_) => crate::name::say!(
                "`pinkvault service install` didn't start the service here; the Mac app does. \
                 Turn it off in System Settings > General > Login Items."
            ),
            None => println!("The service wasn't installed."),
        },
        Err(e) => return Err(e).with_context(|| format!("can't remove {}", path.display())),
    }
    #[cfg(target_os = "linux")]
    systemctl(&["daemon-reload"])?;
    Ok(())
}

pub fn status(home: &Home) -> Result<()> {
    let path = definition_path()?;
    let app = app_state()?;
    let installed = path.exists();
    match (installed, &app) {
        (true, _) => println!("Installed    {}", path.display()),
        (false, Some((label, _))) => println!("Installed    by the Mac app ({label})"),
        (false, None) => println!("Installed    no"),
    }
    for (old, name) in old_definitions()? {
        crate::name::say!(
            "Also installed {}, {name}'s service from before 0.7. `pinkvault service install` \
             replaces it.",
            old.display()
        );
    }
    if installed && app.is_some() {
        crate::name::say!(
            "Both this definition and the Mac app start the service, and only one service runs. \
             `pinkvault service uninstall` removes this one."
        );
    }
    let by_app = !installed && app.is_some();
    let state = match app {
        Some((_, state)) if by_app => state,
        _ => system_state()?,
    };
    let manager = if cfg!(target_os = "macos") {
        "launchd"
    } else {
        "systemd"
    };
    match (state.running, state.pid) {
        (true, Some(pid)) => println!("{manager:<12} running, pid {pid}"),
        (true, None) => println!("{manager:<12} running"),
        (false, _) if state.loaded => println!("{manager:<12} loaded, not running"),
        (false, _) => println!("{manager:<12} not running it"),
    }
    let socket = home.0.join(SOCKET);
    match call_status(&socket) {
        Some(Response::Status {
            version,
            pid,
            mdns_stops,
        }) => {
            println!("Service      pinkvault {version}, pid {pid}");
            println!("This binary  pinkvault {VERSION}");
            println!("mDNS         stopped {mdns_stops} times since the service started");
            if version != VERSION && by_app {
                println!("The service runs the Mac app's build. Updating the app moves it on.");
            } else if version != VERSION {
                crate::name::say!(
                    "The service runs another build. `pinkvault service install` moves it onto \
                     this one."
                );
            }
        }
        Some(_) => crate::name::say!(
            "Service      an older build, from before 0.2.2. `pinkvault service install` moves \
             it onto this one."
        ),
        None => println!("Service      not answering on {}", socket.display()),
    }
    Ok(())
}

/// Whether the service is installed to start at login, under this name or an old one, which
/// `pinkvault keys passphrase` warns about.
pub fn installed() -> bool {
    definition_path().is_ok_and(|path| path.exists())
        || old_definitions().is_ok_and(|old| !old.is_empty())
}

/// The definitions here with an old name, each with the command it was for.
fn old_definitions() -> Result<Vec<(PathBuf, &'static str)>> {
    Ok(old_definition_paths()?
        .into_iter()
        .filter(|(path, _)| path.exists())
        .collect())
}

/// Why a definition with an old name stops the vault moving: it would start a build that looks
/// for the vault only in the old directories. Not when it starts this binary, which was put in
/// the old one's place.
pub(crate) fn old_definition_blocks_move() -> Option<String> {
    let exe = this_binary().ok()?;
    let stable = utf8(&stable(&exe)).ok()?;
    old_definitions()
        .ok()?
        .into_iter()
        .find_map(|(path, name)| {
            let contents = fs::read_to_string(&path).ok()?;
            if runs(&contents, exe.to_str()?) || runs(&contents, &stable) {
                return None;
            }
            Some(format!(
                "{} starts {name}'s service at login, which doesn't look for the vault in \
             ~/.pinkvault. Run `pinkvault service install`: it replaces that service and moves \
             the vault",
                path.display()
            ))
        })
}

/// Why the Mac app stops the vault moving: an agent from before the app was PinkVault runs the
/// app's build of the service, which may look for the vault only in the old directories. Not
/// when that agent started this process, or when `HOME` isn't this account's, so not the
/// directory the app uses.
pub(crate) fn app_blocks_move() -> Option<String> {
    if !cfg!(target_os = "macos") || !migrate::home_is_the_accounts() {
        return None;
    }
    let this_agent = std::env::var("XPC_SERVICE_NAME").ok();
    let label = OLD_APP_LABELS
        .into_iter()
        .filter(|label| this_agent.as_deref() != Some(*label))
        .find(|label| agent_state(label).is_some())?;
    Some(format!(
        "the Mac app starts the service on this Mac ({label}), with a build from before \
         PinkVault. Update the app, or turn it off in System Settings > General > Login Items, \
         then run any `pinkvault` command"
    ))
}

/// This binary's path, with every link resolved.
fn this_binary() -> Result<PathBuf> {
    std::env::current_exe()
        .and_then(fs::canonicalize)
        .context("can't find this binary")
}

/// The path a definition should start for `exe`, a resolved path. For a Homebrew install that's
/// the formula's `opt` link, not the versioned keg `exe` resolves into: `brew upgrade` moves
/// `opt` onto the new keg and deletes the old one, which a definition naming the keg would go on
/// starting. Only when `opt` leads to `exe` itself, so the service starts what was installed.
fn stable(exe: &Path) -> PathBuf {
    homebrew_opt(exe)
        .filter(|opt| fs::canonicalize(opt).is_ok_and(|target| target == exe))
        .unwrap_or_else(|| exe.to_owned())
}

/// `<prefix>/opt/<formula>/bin/<name>` for `<prefix>/Cellar/<formula>/<version>/bin/<name>`, the
/// way Homebrew lays out a keg on macOS and on Linux. Worked out from the path alone.
fn homebrew_opt(exe: &Path) -> Option<PathBuf> {
    let name = exe.file_name()?;
    let bin = exe.parent()?;
    let keg = bin.parent()?;
    let formula = keg.parent()?;
    let cellar = formula.parent()?;
    if bin.file_name()? != "bin" || cellar.file_name()? != "Cellar" {
        return None;
    }
    Some(
        cellar
            .parent()?
            .join("opt")
            .join(formula.file_name()?)
            .join("bin")
            .join(name),
    )
}

impl Definition {
    fn for_this_binary() -> Result<Self> {
        let exe = stable(&this_binary()?);
        let home = match home::var_os(HOME_VAR, &OLD_HOME_VARS) {
            Some(dir) => Some(std::path::absolute(PathBuf::from(dir))?),
            None => None,
        };
        Ok(Self {
            exe: utf8(&exe)?,
            home: home.as_deref().map(utf8).transpose()?,
        })
    }
}

fn utf8(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .with_context(|| format!("{} isn't UTF-8, which a definition needs", path.display()))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// The LaunchAgent (service.md, starting at login).
fn plist(definition: &Definition, log: &str) -> String {
    let mut environment = String::new();
    if let Some(home) = &definition.home {
        environment = format!(
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>PINKVAULT_HOME</key>\n\
             \t\t<string>{}</string>\n\t</dict>\n",
            xml(home)
        );
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- Written by `pinkvault service install`: runs `pinkvault service` at login, and again
     whenever it stops. `pinkvault service uninstall` removes it. -->
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe}</string>
		<string>service</string>
	</array>
{environment}	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>StandardOutPath</key>
	<string>{log}</string>
	<key>StandardErrorPath</key>
	<string>{log}</string>
</dict>
</plist>
"#,
        exe = xml(&definition.exe),
        log = xml(log),
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// The systemd user unit (service.md, starting at login).
fn unit(definition: &Definition) -> String {
    let mut unit = format!(
        "# Written by `pinkvault service install`. `pinkvault service uninstall` removes it.\n\
         [Unit]\n\
         Description=PinkVault service: holds the vault open and syncs it with the other devices\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={} service\n",
        // ExecStart expands $ as well as %.
        systemd_quote(&definition.exe).replace('$', "$$"),
    );
    if let Some(home) = &definition.home {
        let _ = writeln!(
            unit,
            "Environment={}",
            systemd_quote(&format!("PINKVAULT_HOME={home}"))
        );
    }
    unit.push_str("Restart=on-failure\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n");
    unit
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// A word in double quotes, with what systemd would read as a specifier or an escape escaped.
fn systemd_quote(word: &str) -> String {
    let escaped = word
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

/// What launchd or systemd says about the service.
#[derive(Debug, Default, PartialEq, Eq)]
struct SystemState {
    loaded: bool,
    running: bool,
    pid: Option<u32>,
    /// Where launchd has the definition from: its file in `~/Library/LaunchAgents` for
    /// `install`'s, and `(submitted by smd.<pid>)` for the Mac app's, which `SMAppService`
    /// registers from the app bundle.
    path: Option<String>,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// The state and pid in `launchctl print`'s output: the first of each at the top level, which
/// is one tab in. Deeper lines describe other things.
fn launchd_state(print: &str) -> SystemState {
    let field = |name: &str| {
        print.lines().find_map(|line| {
            line.strip_prefix('\t')
                .filter(|rest| !rest.starts_with('\t'))
                .and_then(|rest| rest.strip_prefix(name))
                .and_then(|rest| rest.strip_prefix(" = "))
        })
    };
    SystemState {
        loaded: true,
        running: field("state") == Some("running"),
        pid: field("pid").and_then(|pid| pid.parse().ok()),
        path: field("path").map(str::to_owned),
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// The state in `systemctl --user show -p LoadState -p ActiveState -p MainPID`'s output.
fn systemd_state(show: &str) -> SystemState {
    let field = |name: &str| {
        show.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
    };
    SystemState {
        loaded: field("LoadState") == Some("loaded"),
        running: field("ActiveState") == Some("active"),
        pid: field("MainPID")
            .and_then(|pid| pid.parse().ok())
            .filter(|&pid| pid != 0),
        path: None,
    }
}

/// Asks the service on `socket` for its status. `None` if nothing answers there.
fn call_status(socket: &Path) -> Option<Response> {
    pinkvault_service::client::call(socket, &Request::Status)
        .ok()
        .flatten()
}

/// Waits for a service other than `old_pid` to answer, and returns its version and pid.
fn wait_for_new_service(socket: &Path, old_pid: Option<u32>) -> Option<(String, u32)> {
    let deadline = Instant::now() + STARTING;
    while Instant::now() < deadline {
        if let Some(Response::Status { version, pid, .. }) = call_status(socket)
            && Some(pid) != old_pid
        {
            return Some((version, pid));
        }
        thread::sleep(Duration::from_millis(250));
    }
    None
}

fn run(program: &str, args: &[&str]) -> Result<Output> {
    Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("can't run {program}"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}

#[cfg(target_os = "macos")]
mod system {
    use super::*;

    fn domain() -> String {
        // SAFETY: geteuid has no preconditions and can't fail.
        format!("gui/{}", unsafe { libc::geteuid() })
    }

    fn target(label: &str) -> String {
        format!("{}/{label}", domain())
    }

    fn definition_of(label: &str) -> Result<PathBuf> {
        let home = std::env::home_dir().context("can't find your home directory")?;
        Ok(home
            .join("Library/LaunchAgents")
            .join(format!("{label}.plist")))
    }

    pub fn definition_path() -> Result<PathBuf> {
        definition_of(LABEL)
    }

    pub fn old_definition_paths() -> Result<Vec<(PathBuf, &'static str)>> {
        OLD_LABELS
            .into_iter()
            .map(|(label, name)| Ok((definition_of(label)?, name)))
            .collect()
    }

    /// Whether the agent launchd has as [`LABEL`] is `install`'s, not the Mac app's.
    fn is_installs(state: &SystemState) -> bool {
        let Ok(ours) = definition_path() else {
            return false;
        };
        match &state.path {
            Some(path) => Path::new(path) == ours,
            None => ours.exists(),
        }
    }

    fn log_path() -> Result<PathBuf> {
        let home = std::env::home_dir().context("can't find your home directory")?;
        Ok(home.join("Library/Logs/pinkvault-service.log"))
    }

    pub fn render(definition: &Definition) -> Result<String> {
        Ok(plist(definition, &utf8(&log_path()?)?))
    }

    /// Whether a definition runs `exe`.
    pub fn runs(definition: &str, exe: &str) -> bool {
        definition.contains(&format!("<string>{}</string>", xml(exe)))
    }

    /// What launchd says about the agent `label`, if it has it loaded.
    pub fn agent_state(label: &str) -> Option<SystemState> {
        let output = run("launchctl", &["print", &target(label)]).ok()?;
        output
            .status
            .success()
            .then(|| launchd_state(&String::from_utf8_lossy(&output.stdout)))
    }

    /// What launchd says about `install`'s agent.
    pub fn system_state() -> Result<SystemState> {
        Ok(agent_state(LABEL).filter(is_installs).unwrap_or_default())
    }

    /// The Mac app's agent and its state, when launchd has it loaded: the app registered it,
    /// and it's on in Login Items.
    pub fn app_state() -> Result<Option<(&'static str, SystemState)>> {
        if let Some(state) = agent_state(APP_LABEL).filter(|state| !is_installs(state)) {
            return Ok(Some((APP_LABEL, state)));
        }
        Ok(OLD_APP_LABELS
            .into_iter()
            .find_map(|label| Some((label, agent_state(label)?))))
    }

    /// Unloads the agent `label`, and waits for launchd to let go of it.
    fn unload(label: &str) -> Result<()> {
        // Not loaded is fine: there's nothing to unload.
        run("launchctl", &["bootout", &target(label)])?;
        // bootout returns before launchd lets go of the job, and a bootstrap until then fails
        // with error 5, so wait for it to go.
        let deadline = Instant::now() + STARTING;
        while agent_state(label).is_some() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    /// Loads the agent afresh, so it runs the definition just written.
    pub fn start(path: &Path) -> Result<()> {
        let path = utf8(path)?;
        unload(LABEL)?;
        let mut failed = String::new();
        for _ in 0..3 {
            let output = run("launchctl", &["bootstrap", &domain(), &path])?;
            if output.status.success() {
                return Ok(());
            }
            failed = stderr(&output);
            // macOS can load a new file in LaunchAgents by itself, which also makes bootstrap
            // fail with error 5. It's loaded then, and a restart runs the new definition.
            if system_state()?.loaded {
                let output = run("launchctl", &["kickstart", "-k", &target(LABEL)])?;
                if output.status.success() {
                    return Ok(());
                }
                failed = stderr(&output);
            }
            thread::sleep(Duration::from_secs(1));
        }
        bail!(
            "launchd didn't take the agent ({failed}). Start it with `launchctl bootstrap {} {path}`",
            domain()
        )
    }

    /// Stops `install`'s agent. Not the Mac app's, which has the same label.
    pub fn stop() -> Result<()> {
        if system_state()?.loaded {
            run("launchctl", &["bootout", &target(LABEL)])?;
        }
        Ok(())
    }

    /// Stops and removes the agents with an old name that are here. Whether there were any.
    pub fn remove_old() -> Result<bool> {
        let mut removed = false;
        for (label, name) in OLD_LABELS {
            let path = definition_of(label)?;
            let loaded = agent_state(label).is_some();
            if !loaded && !path.exists() {
                continue;
            }
            unload(label)?;
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("can't remove {}", path.display()));
                }
            }
            println!("Stopped and removed {name}'s service ({label}).");
            removed = true;
        }
        Ok(removed)
    }

    pub fn where_it_logs() -> String {
        match log_path() {
            Ok(path) => format!("Its log is {}.", path.display()),
            Err(_) => String::new(),
        }
    }

    pub fn after_install() -> Result<()> {
        println!(
            "macOS may show \"Background Items Added\", and ask whether pinkvault may find \
             devices on your local network. Allow it, or this Mac can't sync. With the firewall \
             on, it also asks whether pinkvault may accept incoming connections. A new build \
             of pinkvault asks again."
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod system {
    use super::*;

    /// The systemd user unit.
    const UNIT: &str = "pinkvault.service";

    fn definition_of(unit: &str) -> Result<PathBuf> {
        let config = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => std::env::home_dir()
                .context("can't find your home directory")?
                .join(".config"),
        };
        Ok(config.join("systemd/user").join(unit))
    }

    pub fn definition_path() -> Result<PathBuf> {
        definition_of(UNIT)
    }

    pub fn old_definition_paths() -> Result<Vec<(PathBuf, &'static str)>> {
        OLD_UNITS
            .into_iter()
            .map(|(unit, name)| Ok((definition_of(unit)?, name)))
            .collect()
    }

    pub fn render(definition: &Definition) -> Result<String> {
        Ok(unit(definition))
    }

    /// Whether a definition runs `exe`.
    pub fn runs(definition: &str, exe: &str) -> bool {
        definition.contains(&format!(
            "ExecStart={} service\n",
            systemd_quote(exe).replace('$', "$$")
        ))
    }

    pub fn systemctl(args: &[&str]) -> Result<()> {
        let output = run("systemctl", &[&["--user"], args].concat())?;
        if output.status.success() {
            return Ok(());
        }
        let message = stderr(&output);
        if message.contains("Failed to connect to bus") || message.contains("No medium found") {
            bail!(
                "there's no systemd user instance here, as in some WSL setups. Start \
                 `pinkvault service` another way"
            );
        }
        bail!("systemctl --user {} failed: {message}", args.join(" "))
    }

    fn unit_state(unit: &str) -> Result<SystemState> {
        let output = run(
            "systemctl",
            &[
                "--user",
                "show",
                unit,
                "-p",
                "LoadState",
                "-p",
                "ActiveState",
                "-p",
                "MainPID",
            ],
        )?;
        if !output.status.success() {
            return Ok(SystemState::default());
        }
        Ok(systemd_state(&String::from_utf8_lossy(&output.stdout)))
    }

    pub fn system_state() -> Result<SystemState> {
        unit_state(UNIT)
    }

    pub fn start(_: &Path) -> Result<()> {
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", UNIT])?;
        systemctl(&["restart", UNIT])
    }

    pub fn stop() -> Result<()> {
        if system_state()?.loaded {
            systemctl(&["disable", "--now", UNIT])?;
        }
        Ok(())
    }

    /// Stops and removes the units with an old name that are here. Whether there were any.
    pub fn remove_old() -> Result<bool> {
        let mut removed = false;
        for (unit, name) in OLD_UNITS {
            let path = definition_of(unit)?;
            let loaded = unit_state(unit)?.loaded;
            if !loaded && !path.exists() {
                continue;
            }
            if loaded {
                systemctl(&["disable", "--now", unit])?;
            }
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("can't remove {}", path.display()));
                }
            }
            systemctl(&["daemon-reload"])?;
            println!("Stopped and removed {name}'s service ({unit}).");
            removed = true;
        }
        Ok(removed)
    }

    /// There's no Mac app here.
    pub fn agent_state(_: &str) -> Option<SystemState> {
        None
    }

    /// There's no Mac app here.
    pub fn app_state() -> Result<Option<(&'static str, SystemState)>> {
        Ok(None)
    }

    pub fn where_it_logs() -> String {
        "Its log: `journalctl --user -u pinkvault`.".to_owned()
    }

    pub fn after_install() -> Result<()> {
        // SAFETY: geteuid has no preconditions and can't fail.
        let uid = unsafe { libc::geteuid() }.to_string();
        let output = run("loginctl", &["show-user", &uid, "-p", "Linger", "--value"])?;
        if String::from_utf8_lossy(&output.stdout).trim() != "yes" {
            println!(
                "It starts when you log in, not when the computer starts. To start it at boot, \
                 run `loginctl enable-linger {}`.",
                std::env::var("USER").unwrap_or(uid)
            );
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod system {
    use super::*;

    fn unsupported<T>() -> Result<T> {
        bail!("starting the service at login works on macOS and Linux only")
    }

    pub fn definition_path() -> Result<PathBuf> {
        unsupported()
    }

    pub fn old_definition_paths() -> Result<Vec<(PathBuf, &'static str)>> {
        unsupported()
    }

    pub fn render(_: &Definition) -> Result<String> {
        unsupported()
    }

    pub fn runs(_: &str, _: &str) -> bool {
        false
    }

    pub fn system_state() -> Result<SystemState> {
        unsupported()
    }

    pub fn start(_: &Path) -> Result<()> {
        unsupported()
    }

    pub fn stop() -> Result<()> {
        unsupported()
    }

    pub fn remove_old() -> Result<bool> {
        Ok(false)
    }

    pub fn agent_state(_: &str) -> Option<SystemState> {
        None
    }

    pub fn app_state() -> Result<Option<(&'static str, SystemState)>> {
        Ok(None)
    }

    pub fn where_it_logs() -> String {
        String::new()
    }

    pub fn after_install() -> Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use system::systemctl;
use system::{
    after_install, agent_state, app_state, definition_path, old_definition_paths, remove_old,
    render, runs, start, stop, system_state, where_it_logs,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_homebrew_keg_is_started_through_opt() {
        for (keg, opt) in [
            (
                "/opt/homebrew/Cellar/pinkvault/0.6.0_1/bin/pinkvault",
                "/opt/homebrew/opt/pinkvault/bin/pinkvault",
            ),
            (
                "/usr/local/Cellar/pinkvault/0.7.0/bin/pinkvault",
                "/usr/local/opt/pinkvault/bin/pinkvault",
            ),
            (
                "/home/linuxbrew/.linuxbrew/Cellar/pinkvault/0.6.0/bin/pinkvault",
                "/home/linuxbrew/.linuxbrew/opt/pinkvault/bin/pinkvault",
            ),
        ] {
            assert_eq!(
                homebrew_opt(Path::new(keg)).as_deref(),
                Some(Path::new(opt))
            );
        }
        for elsewhere in [
            "/Users/me/.cargo/bin/pinkvault",
            "/Users/me/.local/bin/pinkvault",
            "/opt/homebrew/Cellar/pinkvault/0.6.0/libexec/pinkvault",
            "/Cellar/x/bin/pinkvault",
            "pinkvault",
        ] {
            assert_eq!(homebrew_opt(Path::new(elsewhere)), None, "{elsewhere}");
        }
    }

    /// The definition names `opt` only when it leads to this very binary: a keg laid out on disk
    /// as Homebrew does, then one whose `opt` has moved on to another version.
    #[cfg(unix)]
    #[test]
    fn opt_is_named_only_when_it_leads_here() {
        let prefix = tempfile::tempdir().unwrap();
        let prefix = fs::canonicalize(prefix.path()).unwrap();
        let keg = |version: &str| {
            let bin = prefix.join("Cellar/pinkvault").join(version).join("bin");
            fs::create_dir_all(&bin).unwrap();
            fs::write(bin.join("pinkvault"), "").unwrap();
            bin.join("pinkvault")
        };
        let old = keg("0.6.0");
        let new = keg("0.7.0");
        fs::create_dir_all(prefix.join("opt")).unwrap();
        let opt = prefix.join("opt/pinkvault");
        std::os::unix::fs::symlink("../Cellar/pinkvault/0.6.0", &opt).unwrap();

        let through_opt = prefix.join("opt/pinkvault/bin/pinkvault");
        assert_eq!(stable(&old), through_opt);
        assert_eq!(stable(&new), new);
        fs::remove_file(&opt).unwrap();
        assert_eq!(stable(&old), old);
    }

    fn definition(exe: &str, home: Option<&str>) -> Definition {
        Definition {
            exe: exe.into(),
            home: home.map(Into::into),
        }
    }

    #[test]
    fn the_plist_runs_this_binary() {
        let plist = plist(
            &definition("/Users/me/.cargo/bin/pinkvault", None),
            "/Users/me/Library/Logs/pinkvault-service.log",
        );
        assert!(plist.contains("<string>com.abyssinialabs.pinkvault.service</string>"));
        assert!(plist.contains(
            "\t\t<string>/Users/me/.cargo/bin/pinkvault</string>\n\t\t<string>service</string>"
        ));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(plist.contains("<integer>30</integer>"));
        assert!(!plist.contains("PINKVAULT_HOME"));
        assert_eq!(
            plist
                .matches("/Users/me/Library/Logs/pinkvault-service.log")
                .count(),
            2
        );
    }

    #[test]
    fn the_plist_escapes_paths_and_carries_the_vault_home() {
        let plist = plist(
            &definition(
                "/Users/me/A & B <x>/pinkvault",
                Some("/Users/me/vault & co"),
            ),
            "/tmp/log",
        );
        assert!(plist.contains("<string>/Users/me/A &amp; B &lt;x&gt;/pinkvault</string>"));
        assert!(
            plist.contains(
                "<key>PINKVAULT_HOME</key>\n\t\t<string>/Users/me/vault &amp; co</string>"
            )
        );
    }

    #[test]
    fn the_unit_runs_this_binary() {
        let unit = unit(&definition("/home/me/.cargo/bin/pinkvault", None));
        assert!(unit.contains("ExecStart=\"/home/me/.cargo/bin/pinkvault\" service\n"));
        assert!(unit.contains("Restart=on-failure\nRestartSec=30\n"));
        assert!(unit.contains("After=network-online.target\n"));
        assert!(unit.contains("[Install]\nWantedBy=default.target\n"));
        assert!(!unit.contains("Environment="));
    }

    #[test]
    fn the_unit_quotes_paths_and_carries_the_vault_home() {
        let unit = unit(&definition(
            "/home/me/my \"tools\" 100%/$bin\\pinkvault",
            Some("/home/me/vault 50%"),
        ));
        assert!(unit.contains(
            "ExecStart=\"/home/me/my \\\"tools\\\" 100%%/$$bin\\\\pinkvault\" service\n"
        ));
        assert!(unit.contains("Environment=\"PINKVAULT_HOME=/home/me/vault 50%%\"\n"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_definition_names_the_binary_it_runs() {
        let exe = "/Users/me/A & B \"100%\"/$bin/pinkvault";
        let written = render(&definition(exe, None)).unwrap();
        assert!(runs(&written, exe));
        assert!(!runs(&written, "/Users/me/A & B \"100%\"/$bin/latem-vault"));
    }

    #[test]
    fn launchd_state_reads_the_top_level() {
        let print = "gui/501/com.abyssinialabs.pinkvault.service = {\n\
                     \tactive count = 2\n\
                     \tpath = /Users/me/Library/LaunchAgents/com.abyssinialabs.pinkvault.service.plist\n\
                     \tstate = running\n\
                     \n\
                     \tprogram = /Users/me/.cargo/bin/pinkvault\n\
                     \tpid = 53589\n\
                     \tendpoints = {\n\
                     \t\tstate = active\n\
                     \t\tpid = 1\n\
                     \t}\n\
                     }\n";
        assert_eq!(
            launchd_state(print),
            SystemState {
                loaded: true,
                running: true,
                pid: Some(53589),
                path: Some(
                    "/Users/me/Library/LaunchAgents/com.abyssinialabs.pinkvault.service.plist"
                        .to_owned()
                ),
            }
        );
        let app = "gui/501/com.abyssinialabs.pinkvault.service = {\n\
                   \tpath = (submitted by smd.539)\n\
                   \tstate = running\n\
                   \tparent bundle identifier = com.abyssinialabs.pinkvault\n\
                   }\n";
        assert_eq!(
            launchd_state(app).path.as_deref(),
            Some("(submitted by smd.539)")
        );
        let waiting = "gui/501/com.abyssinialabs.pinkvault.service = {\n\tstate = waiting\n}\n";
        assert_eq!(
            launchd_state(waiting),
            SystemState {
                loaded: true,
                running: false,
                pid: None,
                path: None,
            }
        );
    }

    #[test]
    fn systemd_state_reads_show() {
        assert_eq!(
            systemd_state("LoadState=loaded\nActiveState=active\nMainPID=1138989\n"),
            SystemState {
                loaded: true,
                running: true,
                pid: Some(1138989),
                path: None,
            }
        );
        assert_eq!(
            systemd_state("LoadState=not-found\nActiveState=inactive\nMainPID=0\n"),
            SystemState::default()
        );
    }
}
