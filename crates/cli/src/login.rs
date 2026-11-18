//! `latem-vault service install | uninstall | status`: having the operating system start the
//! service at login (service.md, starting at login). A LaunchAgent on macOS and a systemd user
//! unit on Linux, each running `latem-vault service` from this binary.
//!
//! Before 0.6 they had openvault's names ([`OLD_LABEL`], [`OLD_UNIT`]). `install` and
//! `uninstall` remove that definition too, so two don't start two services for one vault.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use latem_vault_keystore::Backend;
use latem_vault_service::SOCKET;
use latem_vault_service::api::{Request, Response};
use latem_vault_service::home::{self, HOME_VAR, Location, OLD_HOME_VAR};

#[cfg_attr(not(target_os = "macos"), allow(unused_imports))]
use crate::migrate::OLD_LABEL;
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use crate::migrate::OLD_UNIT;
use crate::migrate::{self, OLD_APP_LABEL};
use crate::{Home, VERSION};

/// The LaunchAgent's label, which also names its file.
const LABEL: &str = "dev.latem.vault.service";
/// The Mac app's own LaunchAgent, which starts the bundled binary instead (service.md, the Mac
/// app), once the app has latem vault's name (OV-12). Until then it's [`OLD_APP_LABEL`].
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const APP_LABEL: &str = "com.abyssinialabs.latemvault.service";
/// How long `install` waits for the new service to answer.
const STARTING: Duration = Duration::from_secs(10);

/// What a definition runs: `latem-vault service` from `exe`, with `LATEM_VAULT_HOME` set to
/// `home` when it, or `OPENVAULT_HOME` before it, was set for `install`.
struct Definition {
    exe: String,
    home: Option<String>,
}

pub fn install() -> Result<()> {
    if app_state()?.is_some() {
        bail!(
            "the Mac app starts the service on this Mac, with its own copy of latem-vault. To \
             have this binary start it instead, turn the app off in System Settings > General > \
             Login Items first"
        );
    }
    // Checked on the directory as it is, before anything is stopped or moved.
    let current = Home(Location::from_env()?.current());
    current.require_vault()?;
    if latem_vault_keystore::backend_of(&current.keys())? == Backend::Passphrase {
        bail!(
            "this device's keys are protected by a passphrase, and a service the system starts \
             has nobody to type it. Either remove the passphrase with `latem-vault keys \
             passphrase --remove`, or start `latem-vault service` by hand after each restart"
        );
    }
    let definition = Definition::for_this_binary()?;
    if definition.exe.contains("/target/debug/") || definition.exe.contains("/target/release/") {
        eprintln!(
            "Warning: {} is in a cargo target directory, which each build replaces. \
             `cargo install --path crates/cli` puts latem-vault somewhere that lasts.",
            definition.exe
        );
    }

    // openvault's service stops here, so the vault can move and only this one starts it.
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
            println!("The service is running: latem-vault {version}, pid {pid}.")
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
            Some(_) => println!(
                "`latem-vault service install` didn't start the service here; the Mac app does. \
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
    if let Some(old) = old_definition_path().ok().filter(|old| old.exists()) {
        println!(
            "Also installed {}, openvault's service from before 0.6. `latem-vault service \
             install` replaces it.",
            old.display()
        );
    }
    if installed && app.is_some() {
        println!(
            "Both this definition and the Mac app start the service, and only one service runs. \
             `latem-vault service uninstall` removes this one."
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
            println!("Service      latem-vault {version}, pid {pid}");
            println!("This binary  latem-vault {VERSION}");
            println!("mDNS         stopped {mdns_stops} times since the service started");
            if version != VERSION && by_app {
                println!("The service runs the Mac app's build. Updating the app moves it on.");
            } else if version != VERSION {
                println!(
                    "The service runs another build. `latem-vault service install` moves it onto \
                     this one."
                );
            }
        }
        Some(_) => println!(
            "Service      an older build, from before 0.2.2. `latem-vault service install` moves \
             it onto this one."
        ),
        None => println!("Service      not answering on {}", socket.display()),
    }
    Ok(())
}

/// Whether the service is installed to start at login, under this name or openvault's, which
/// `latem-vault keys passphrase` warns about.
pub fn installed() -> bool {
    [definition_path(), old_definition_path()]
        .into_iter()
        .any(|path| path.is_ok_and(|path| path.exists()))
}

/// Why openvault's definition stops the vault moving: it would start a build that looks for
/// the vault only in the old directory. Not when it starts this binary, which was put in the
/// old one's place.
pub(crate) fn old_definition_blocks_move() -> Option<String> {
    let path = old_definition_path().ok()?;
    let contents = fs::read_to_string(&path).ok()?;
    let exe = std::env::current_exe().and_then(fs::canonicalize).ok()?;
    if runs(&contents, exe.to_str()?) {
        return None;
    }
    Some(format!(
        "{} starts openvault's service at login, which looks for the vault only there. Run \
         `latem-vault service install`: it replaces that service and moves the vault",
        path.display()
    ))
}

/// Why the Mac app stops the vault moving: its agent runs the app's build of the service, which
/// may look for the vault only in the old directory. Not when that agent started this process,
/// or when `HOME` isn't this account's, so not the directory the app uses.
pub(crate) fn app_blocks_move() -> Option<String> {
    if !cfg!(target_os = "macos")
        || !migrate::home_is_the_accounts()
        || std::env::var("XPC_SERVICE_NAME").is_ok_and(|name| name == OLD_APP_LABEL)
    {
        return None;
    }
    agent_state(OLD_APP_LABEL)?;
    Some(
        "the Mac app starts the service on this Mac. Its service moves the vault when it starts \
         with an app built from latem vault 0.6 or later"
            .to_owned(),
    )
}

impl Definition {
    fn for_this_binary() -> Result<Self> {
        let exe = std::env::current_exe()
            .and_then(fs::canonicalize)
            .context("can't find this binary")?;
        let home = match home::var_os(HOME_VAR, OLD_HOME_VAR) {
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
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>LATEM_VAULT_HOME</key>\n\
             \t\t<string>{}</string>\n\t</dict>\n",
            xml(home)
        );
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- Written by `latem-vault service install`: runs `latem-vault service` at login, and again
     whenever it stops. `latem-vault service uninstall` removes it. -->
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
        "# Written by `latem-vault service install`. `latem-vault service uninstall` removes it.\n\
         [Unit]\n\
         Description=latem vault service: holds the vault open and syncs it with the other devices\n\
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
            systemd_quote(&format!("LATEM_VAULT_HOME={home}"))
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
    }
}

/// Asks the service on `socket` for its status. `None` if nothing answers there.
fn call_status(socket: &Path) -> Option<Response> {
    latem_vault_service::client::call(socket, &Request::Status)
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

    pub fn old_definition_path() -> Result<PathBuf> {
        definition_of(OLD_LABEL)
    }

    fn log_path() -> Result<PathBuf> {
        let home = std::env::home_dir().context("can't find your home directory")?;
        Ok(home.join("Library/Logs/latem-vault-service.log"))
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

    pub fn system_state() -> Result<SystemState> {
        Ok(agent_state(LABEL).unwrap_or_default())
    }

    /// The Mac app's agent and its state, when launchd has it loaded: the app registered it,
    /// and it's on in Login Items.
    pub fn app_state() -> Result<Option<(&'static str, SystemState)>> {
        Ok([APP_LABEL, OLD_APP_LABEL]
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

    pub fn stop() -> Result<()> {
        run("launchctl", &["bootout", &target(LABEL)])?;
        Ok(())
    }

    /// Stops and removes openvault's agent, if it's here. Whether it was.
    pub fn remove_old() -> Result<bool> {
        let path = old_definition_path()?;
        let loaded = agent_state(OLD_LABEL).is_some();
        if !loaded && !path.exists() {
            return Ok(false);
        }
        unload(OLD_LABEL)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("can't remove {}", path.display())),
        }
        println!("Stopped and removed openvault's service ({OLD_LABEL}).");
        Ok(true)
    }

    pub fn where_it_logs() -> String {
        match log_path() {
            Ok(path) => format!("Its log is {}.", path.display()),
            Err(_) => String::new(),
        }
    }

    pub fn after_install() -> Result<()> {
        println!(
            "macOS may show \"Background Items Added\", and ask whether latem-vault may find \
             devices on your local network. Allow it, or this Mac can't sync. With the firewall \
             on, it also asks whether latem-vault may accept incoming connections. A new build \
             of latem-vault asks again."
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod system {
    use super::*;

    /// The systemd user unit.
    const UNIT: &str = "latem-vault.service";

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

    pub fn old_definition_path() -> Result<PathBuf> {
        definition_of(OLD_UNIT)
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
                 `latem-vault service` another way"
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

    /// Stops and removes openvault's unit, if it's here. Whether it was.
    pub fn remove_old() -> Result<bool> {
        let path = old_definition_path()?;
        let loaded = unit_state(OLD_UNIT)?.loaded;
        if !loaded && !path.exists() {
            return Ok(false);
        }
        if loaded {
            systemctl(&["disable", "--now", OLD_UNIT])?;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("can't remove {}", path.display())),
        }
        systemctl(&["daemon-reload"])?;
        println!("Stopped and removed openvault's service ({OLD_UNIT}).");
        Ok(true)
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
        "Its log: `journalctl --user -u latem-vault`.".to_owned()
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

    pub fn old_definition_path() -> Result<PathBuf> {
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
    after_install, agent_state, app_state, definition_path, old_definition_path, remove_old,
    render, runs, start, stop, system_state, where_it_logs,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(exe: &str, home: Option<&str>) -> Definition {
        Definition {
            exe: exe.into(),
            home: home.map(Into::into),
        }
    }

    #[test]
    fn the_plist_runs_this_binary() {
        let plist = plist(
            &definition("/Users/me/.cargo/bin/latem-vault", None),
            "/Users/me/Library/Logs/latem-vault-service.log",
        );
        assert!(plist.contains("<string>dev.latem.vault.service</string>"));
        assert!(plist.contains(
            "\t\t<string>/Users/me/.cargo/bin/latem-vault</string>\n\t\t<string>service</string>"
        ));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(plist.contains("<integer>30</integer>"));
        assert!(!plist.contains("LATEM_VAULT_HOME"));
        assert_eq!(
            plist
                .matches("/Users/me/Library/Logs/latem-vault-service.log")
                .count(),
            2
        );
    }

    #[test]
    fn the_plist_escapes_paths_and_carries_the_vault_home() {
        let plist = plist(
            &definition(
                "/Users/me/A & B <x>/latem-vault",
                Some("/Users/me/vault & co"),
            ),
            "/tmp/log",
        );
        assert!(plist.contains("<string>/Users/me/A &amp; B &lt;x&gt;/latem-vault</string>"));
        assert!(plist.contains(
            "<key>LATEM_VAULT_HOME</key>\n\t\t<string>/Users/me/vault &amp; co</string>"
        ));
    }

    #[test]
    fn the_unit_runs_this_binary() {
        let unit = unit(&definition("/home/me/.cargo/bin/latem-vault", None));
        assert!(unit.contains("ExecStart=\"/home/me/.cargo/bin/latem-vault\" service\n"));
        assert!(unit.contains("Restart=on-failure\nRestartSec=30\n"));
        assert!(unit.contains("After=network-online.target\n"));
        assert!(unit.contains("[Install]\nWantedBy=default.target\n"));
        assert!(!unit.contains("Environment="));
    }

    #[test]
    fn the_unit_quotes_paths_and_carries_the_vault_home() {
        let unit = unit(&definition(
            "/home/me/my \"tools\" 100%/$bin\\latem-vault",
            Some("/home/me/vault 50%"),
        ));
        assert!(unit.contains(
            "ExecStart=\"/home/me/my \\\"tools\\\" 100%%/$$bin\\\\latem-vault\" service\n"
        ));
        assert!(unit.contains("Environment=\"LATEM_VAULT_HOME=/home/me/vault 50%%\"\n"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_definition_names_the_binary_it_runs() {
        let exe = "/Users/me/A & B \"100%\"/$bin/latem-vault";
        let written = render(&definition(exe, None)).unwrap();
        assert!(runs(&written, exe));
        assert!(!runs(&written, "/Users/me/A & B \"100%\"/$bin/openvault"));
    }

    #[test]
    fn launchd_state_reads_the_top_level() {
        let print = "gui/501/dev.latem.vault.service = {\n\
                     \tactive count = 2\n\
                     \tpath = /Users/me/Library/LaunchAgents/dev.latem.vault.service.plist\n\
                     \tstate = running\n\
                     \n\
                     \tprogram = /Users/me/.cargo/bin/latem-vault\n\
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
            }
        );
        let waiting = "gui/501/dev.latem.vault.service = {\n\tstate = waiting\n}\n";
        assert_eq!(
            launchd_state(waiting),
            SystemState {
                loaded: true,
                running: false,
                pid: None,
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
            }
        );
        assert_eq!(
            systemd_state("LoadState=not-found\nActiveState=inactive\nMainPID=0\n"),
            SystemState::default()
        );
    }
}
