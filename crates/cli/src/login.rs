//! `openvault service install | uninstall | status`: having the operating system start the
//! service at login (service.md, starting at login). A LaunchAgent on macOS and a systemd user
//! unit on Linux, each running `openvault service` from this binary.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use openvault_keystore::Backend;
use openvault_service::SOCKET;
use openvault_service::api::{Request, Response};

use crate::{Home, VERSION};

/// The LaunchAgent's label, which also names its file.
const LABEL: &str = "local.openvault.service";
/// How long `install` waits for the new service to answer.
const STARTING: Duration = Duration::from_secs(10);

/// What a definition runs: `openvault service` from `exe`, with `OPENVAULT_HOME` set to `home`
/// when it was set for `install`.
struct Definition {
    exe: String,
    home: Option<String>,
}

pub fn install(home: &Home) -> Result<()> {
    home.require_vault()?;
    if openvault_keystore::backend_of(&home.keys())? == Backend::Passphrase {
        bail!(
            "this device's keys are protected by a passphrase, and a service the system starts \
             has nobody to type it. Either remove the passphrase with `openvault keys passphrase \
             --remove`, or start `openvault service` by hand after each restart"
        );
    }
    let definition = Definition::for_this_binary()?;
    if definition.exe.contains("/target/debug/") || definition.exe.contains("/target/release/") {
        eprintln!(
            "Warning: {} is in a cargo target directory, which each build replaces. \
             `cargo install --path crates/cli` puts openvault somewhere that lasts.",
            definition.exe
        );
    }

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
        Some((version, pid)) => println!("The service is running: openvault {version}, pid {pid}."),
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
    match fs::remove_file(&path) {
        Ok(()) => println!("Removed {}. The vault is untouched.", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("The service wasn't installed.");
        }
        Err(e) => return Err(e).with_context(|| format!("can't remove {}", path.display())),
    }
    #[cfg(target_os = "linux")]
    systemctl(&["daemon-reload"])?;
    Ok(())
}

pub fn status(home: &Home) -> Result<()> {
    let path = definition_path()?;
    if path.exists() {
        println!("Installed    {}", path.display());
    } else {
        println!("Installed    no");
    }
    let state = system_state()?;
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
            println!("Service      openvault {version}, pid {pid}");
            println!("This binary  openvault {VERSION}");
            println!("mDNS         stopped {mdns_stops} times since the service started");
            if version != VERSION {
                println!(
                    "The service runs another build. `openvault service install` moves it onto \
                     this one."
                );
            }
        }
        Some(_) => println!(
            "Service      an older build, from before 0.2.2. `openvault service install` moves \
             it onto this one."
        ),
        None => println!("Service      not answering on {}", socket.display()),
    }
    Ok(())
}

/// Whether the service is installed to start at login, which `openvault keys passphrase` warns
/// about.
pub fn installed() -> bool {
    definition_path().is_ok_and(|path| path.exists())
}

impl Definition {
    fn for_this_binary() -> Result<Self> {
        let exe = std::env::current_exe()
            .and_then(fs::canonicalize)
            .context("can't find this binary")?;
        let home = match std::env::var_os("OPENVAULT_HOME") {
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
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>OPENVAULT_HOME</key>\n\
             \t\t<string>{}</string>\n\t</dict>\n",
            xml(home)
        );
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- Written by `openvault service install`: runs `openvault service` at login, and again
     whenever it stops. `openvault service uninstall` removes it. -->
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
        "# Written by `openvault service install`. `openvault service uninstall` removes it.\n\
         [Unit]\n\
         Description=OpenVault service: holds the vault open and syncs it with the other devices\n\
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
            systemd_quote(&format!("OPENVAULT_HOME={home}"))
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
    openvault_service::client::call(socket, &Request::Status)
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

    fn target() -> String {
        format!("{}/{LABEL}", domain())
    }

    pub fn definition_path() -> Result<PathBuf> {
        let home = std::env::home_dir().context("can't find your home directory")?;
        Ok(home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    }

    fn log_path() -> Result<PathBuf> {
        let home = std::env::home_dir().context("can't find your home directory")?;
        Ok(home.join("Library/Logs/openvault-service.log"))
    }

    pub fn render(definition: &Definition) -> Result<String> {
        Ok(plist(definition, &utf8(&log_path()?)?))
    }

    pub fn system_state() -> Result<SystemState> {
        let output = run("launchctl", &["print", &target()])?;
        if !output.status.success() {
            return Ok(SystemState::default());
        }
        Ok(launchd_state(&String::from_utf8_lossy(&output.stdout)))
    }

    /// Loads the agent afresh, so it runs the definition just written.
    pub fn start(path: &Path) -> Result<()> {
        let path = utf8(path)?;
        // Not loaded is fine: there's nothing to unload.
        run("launchctl", &["bootout", &target()])?;
        // bootout returns before launchd lets go of the job, and a bootstrap until then fails
        // with error 5, so wait for it to go.
        let deadline = Instant::now() + STARTING;
        while system_state()?.loaded && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(250));
        }
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
                let output = run("launchctl", &["kickstart", "-k", &target()])?;
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
        run("launchctl", &["bootout", &target()])?;
        Ok(())
    }

    pub fn where_it_logs() -> String {
        match log_path() {
            Ok(path) => format!("Its log is {}.", path.display()),
            Err(_) => String::new(),
        }
    }

    pub fn after_install() -> Result<()> {
        println!(
            "macOS may show \"Background Items Added\", and ask whether openvault may find \
             devices on your local network. Allow it, or this Mac can't sync. With the firewall \
             on, it also asks whether openvault may accept incoming connections. A new build of \
             openvault asks again."
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod system {
    use super::*;

    /// The systemd user unit.
    const UNIT: &str = "openvault.service";

    pub fn definition_path() -> Result<PathBuf> {
        let config = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => std::env::home_dir()
                .context("can't find your home directory")?
                .join(".config"),
        };
        Ok(config.join("systemd/user").join(UNIT))
    }

    pub fn render(definition: &Definition) -> Result<String> {
        Ok(unit(definition))
    }

    pub fn systemctl(args: &[&str]) -> Result<()> {
        let output = run("systemctl", &[&["--user"], args].concat())?;
        if output.status.success() {
            return Ok(());
        }
        let message = stderr(&output);
        if message.contains("Failed to connect to bus") || message.contains("No medium found") {
            bail!(
                "there's no systemd user instance here, as in some WSL setups. Start `openvault \
                 service` another way"
            );
        }
        bail!("systemctl --user {} failed: {message}", args.join(" "))
    }

    pub fn system_state() -> Result<SystemState> {
        let output = run(
            "systemctl",
            &[
                "--user",
                "show",
                UNIT,
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

    pub fn where_it_logs() -> String {
        "Its log: `journalctl --user -u openvault`.".to_owned()
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

    pub fn render(_: &Definition) -> Result<String> {
        unsupported()
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

    pub fn where_it_logs() -> String {
        String::new()
    }

    pub fn after_install() -> Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use system::systemctl;
use system::{after_install, definition_path, render, start, stop, system_state, where_it_logs};

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
            &definition("/Users/me/.cargo/bin/openvault", None),
            "/Users/me/Library/Logs/openvault-service.log",
        );
        assert!(plist.contains("<string>local.openvault.service</string>"));
        assert!(plist.contains(
            "\t\t<string>/Users/me/.cargo/bin/openvault</string>\n\t\t<string>service</string>"
        ));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(plist.contains("<integer>30</integer>"));
        assert!(!plist.contains("OPENVAULT_HOME"));
        assert_eq!(
            plist
                .matches("/Users/me/Library/Logs/openvault-service.log")
                .count(),
            2
        );
    }

    #[test]
    fn the_plist_escapes_paths_and_carries_openvault_home() {
        let plist = plist(
            &definition(
                "/Users/me/A & B <x>/openvault",
                Some("/Users/me/vault & co"),
            ),
            "/tmp/log",
        );
        assert!(plist.contains("<string>/Users/me/A &amp; B &lt;x&gt;/openvault</string>"));
        assert!(
            plist.contains(
                "<key>OPENVAULT_HOME</key>\n\t\t<string>/Users/me/vault &amp; co</string>"
            )
        );
    }

    #[test]
    fn the_unit_runs_this_binary() {
        let unit = unit(&definition("/home/me/.cargo/bin/openvault", None));
        assert!(unit.contains("ExecStart=\"/home/me/.cargo/bin/openvault\" service\n"));
        assert!(unit.contains("Restart=on-failure\nRestartSec=30\n"));
        assert!(unit.contains("After=network-online.target\n"));
        assert!(unit.contains("[Install]\nWantedBy=default.target\n"));
        assert!(!unit.contains("Environment="));
    }

    #[test]
    fn the_unit_quotes_paths_and_carries_openvault_home() {
        let unit = unit(&definition(
            "/home/me/my \"tools\" 100%/$bin\\openvault",
            Some("/home/me/vault 50%"),
        ));
        assert!(unit.contains(
            "ExecStart=\"/home/me/my \\\"tools\\\" 100%%/$$bin\\\\openvault\" service\n"
        ));
        assert!(unit.contains("Environment=\"OPENVAULT_HOME=/home/me/vault 50%%\"\n"));
    }

    #[test]
    fn launchd_state_reads_the_top_level() {
        let print = "gui/501/local.openvault.service = {\n\
                     \tactive count = 2\n\
                     \tpath = /Users/me/Library/LaunchAgents/local.openvault.service.plist\n\
                     \tstate = running\n\
                     \n\
                     \tprogram = /Users/me/.cargo/bin/openvault\n\
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
        let waiting = "gui/501/local.openvault.service = {\n\tstate = waiting\n}\n";
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
