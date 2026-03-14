use std::{
    collections::hash_map::DefaultHasher,
    env, fs,
    fmt,
    hash::{Hash, Hasher},
    io::{self, BufRead, BufReader, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{Executor, ExitKind, HasObservers},
    feedback_and,
    feedbacks::{CrashFeedback, NewHashFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasBytesVec, HasTargetBytes, UsesInput},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, MutationResult, Mutator, StdScheduledMutator},
    observers::{Observer, ObserversTuple, ObserverWithHashField, TimeObserver, UsesObservers},
    schedulers::QueueScheduler,
    stages::{IfStage, StdMutationalStage, SyncFromDiskStage},
    state::{HasCorpus, HasExecutions, HasRand, HasSolutions, State, StdState, UsesState},
    Error,
};
use libafl_bolts::{
    current_nanos,
    rands::{Rand, StdRand},
    tuples::{tuple_list, MatchName},
    AsSlice, Named,
};
use serde::{Deserialize, Serialize};

const DEFAULT_QEMU_BIN: &str = "/usr/bin/qemu-system-x86_64";
const DEFAULT_MACHINE: &str = "pc";
const DEFAULT_SEED_DIR: &str = "corpus";
const DEFAULT_CRASH_DIR: &str = "crashes";
const DEFAULT_SYNC_DIR: &str = "sync";
const DEFAULT_ITERS: u64 = 5000;
const DEFAULT_TIMEOUT_MS: u64 = 1200;
const DEFAULT_MAX_COMMANDS: usize = 16;
const DEFAULT_SYNC_INTERVAL: u64 = 50;
/// How many testcases to run in a single persistent QEMU session before restarting.
/// Amortises QEMU startup cost (~57 ms vanilla, ~1400 ms ASan) over many runs.
const DEFAULT_SESSION_LENGTH: usize = 500;

const DEVICE_DRIVERS: &[&str] = &[
    // PCI NIC drivers – all hotplug-capable on i440fx (pc) machine
    "e1000",
    "rtl8139",
    "ne2k_pci",
    "pcnet",
    "virtio-net-pci",
    // Virtio device family
    "virtio-rng-pci",
    "virtio-serial-pci",
    "virtio-balloon-pci",
    "virtio-scsi-pci",
    // USB input devices (require ich9-usb-uhci1 in base command)
    "usb-mouse",
    "usb-kbd",
    "usb-tablet",
    "usb-storage",
    "usb-audio",
    // Test/debug devices
    "pci-testdev",
    "edu",
    // Additional NIC variants
    "i82557a",
    "e1000e",
    "vmxnet3",
    // Audio
    "intel-hda",
    "hda-duplex",
    // Additional virtio
    "virtio-rng-pci",
];
const QUERY_COMMANDS: &[&str] = &[
    "query-status",
    "query-version",
    "query-pci",
    "query-machines",
    "query-cpus-fast",
    "query-hotpluggable-cpus",
    "query-memory-devices",
    "query-iothreads",
    "query-target",
    "query-blockdev",
    "query-chardev",
    "query-commands",
    "query-block",
    "query-netdev",
    "query-migrate",
    "query-acpi-ospm-status",
];
const HMP_COMMANDS: &[&str] = &[
    "help",
    "info pci",
    "info qtree",
    "info mtree",
    "info block",
    "info network",
    "info qom-tree",
    "info version",    // was "info irq" - IRQ counts are non-deterministic (timer fires)
    "info kvm",        // was "info cpu" - pc=0x value varies with SeaBIOS execution
    "info mem",
    "info lapic",      // was "info registers" - CPU registers vary with SeaBIOS
    "info blockstats",
    "info usb",
    "info balloon",
    "info mice",
];
/// Qcodes for the QMP `send-key` command.  These keys exercise:
///   - i8042 PS/2 keyboard controller scancode translation
///   - SeaBIOS keyboard interrupt handler (IRQ 1)
///   - ACPI wake-from-S3 path (ctrl-alt-del triggers warm reset)
const SENDKEY_KEYS: &[&str] = &[
    "ret", "esc", "tab", "spc", "backspace",
    "f1", "f2", "f8", "f10", "f12",
    "ctrl-alt-delete",
    "ctrl-c", "ctrl-d", "ctrl-z",
    "alt-f4",
    "a", "b", "c", "x", "y", "z",
    "0", "1", "9",
    "up", "down", "left", "right",
];
const CHARDEV_BACKENDS: &[&str] = &["null", "memory", "ringbuf"];
const QOM_PATHS: &[&str] = &[
    "/machine",
    "/machine/peripheral",
    "/machine/unattached",
    "/objects",
    "/chardevs",
];
const QOM_PROPERTIES: &[&str] = &["type", "id", "realized", "hotplugged", "driver", "name"];
const CMDLINE_OPTIONS: &[&str] = &["device", "machine", "cpu", "accel", "netdev"];
const OBJECT_TYPES: &[&str] = &["rng-random", "iothread", "memory-backend-ram"];

// Op 18: balloon target sizes in MB (powers-of-two, 32 MB … 4 GB)
const BALLOON_SIZES_MB: &[u64] = &[32, 64, 128, 256, 512, 1024, 2048, 4096];
// Op 21: set-action — controls QEMU response to VM lifecycle events
const SHUTDOWN_ACTIONS: &[&str] = &["poweroff", "pause", "shutdown", "ignore"];
const REBOOT_ACTIONS:   &[&str] = &["reset",    "shutdown", "ignore"];
const PANIC_ACTIONS:    &[&str] = &["pause",    "shutdown", "none"];
// Op 22: migrate-set-parameters — key/value pairs to fuzz the migration engine
const MIGRATE_PARAMS: &[(&str, &str)] = &[
    ("max-bandwidth",          "0"),
    ("max-bandwidth",          "1073741824"),
    ("downtime-limit",         "300"),
    ("downtime-limit",         "0"),
    ("cpu-throttle-initial",   "20"),
    ("xbzrle-cache-size",      "67108864"),
    ("multifd-channels",       "1"),
    ("multifd-channels",       "255"),
];
// Op 23: migrate-set-capabilities flags (all combinable, bool state)
const MIGRATE_CAPS: &[&str] = &[
    "xbzrle", "rdma-pin-all", "auto-converge", "zero-blocks",
    "compress", "events", "postcopy-ram", "x-colo",
];

#[derive(Debug, Clone)]
struct Config {
    qemu_bin: PathBuf,
    machine: String,
    seed_dir: PathBuf,
    crashes_dir: PathBuf,
    sync_dir: PathBuf,
    iterations: u64,
    timeout_ms: u64,
    max_commands: usize,
    jobs: usize,
    worker_id: Option<usize>,
    sync_interval: u64,
    debug_qemu: bool,
    validate_dir: Option<PathBuf>,
    validated_dir: Option<PathBuf>,
    /// Testcases per persistent QEMU session (0 = spawn-per-testcase fallback).
    session_length: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            qemu_bin: PathBuf::from(DEFAULT_QEMU_BIN),
            machine: DEFAULT_MACHINE.to_string(),
            seed_dir: PathBuf::from(DEFAULT_SEED_DIR),
            crashes_dir: PathBuf::from(DEFAULT_CRASH_DIR),
            sync_dir: PathBuf::from(DEFAULT_SYNC_DIR),
            iterations: DEFAULT_ITERS,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_commands: DEFAULT_MAX_COMMANDS,
            jobs: 1,
            worker_id: None,
            sync_interval: DEFAULT_SYNC_INTERVAL,
            debug_qemu: false,
            validate_dir: None,
            validated_dir: None,
            session_length: DEFAULT_SESSION_LENGTH,
        }
    }
}

#[derive(Debug, Clone)]
struct WorkerPaths {
    queue_root: PathBuf,
    worker_queue_dir: PathBuf,
    objective_root: PathBuf,
    worker_objective_base_dir: PathBuf,
    worker_objective_all_dir: PathBuf,
    worker_crash_only_dir: PathBuf,
    worker_timeout_dir: PathBuf,
    worker_unknown_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StdOutHashObserver {
    name: String,
    hash: Option<u64>,
}

impl StdOutHashObserver {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            hash: None,
        }
    }
}

impl Named for StdOutHashObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl ObserverWithHashField for StdOutHashObserver {
    fn hash(&self) -> Option<u64> {
        self.hash
    }
}

impl<S> Observer<S> for StdOutHashObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.hash = None;
        Ok(())
    }

    fn observes_stdout(&self) -> bool {
        true
    }

    fn observe_stdout(&mut self, stdout: &[u8]) {
        // Coarse structural hash: instead of hashing full normalised response content
        // (which produces a near-unique hash for every distinct input because even minor
        // argument differences yield different JSON — causing 10M+ corpus entries in 24h),
        // we reduce each response line to a short type-token:
        //
        //   R0  – {"return": {}} or {"return": []}   empty success
        //   RA  – {"return": [...]                   array success
        //   RO  – {"return": {...}                   object success
        //   RS  – {"return": "..."                   string (HMP) success
        //   RN  – {"return": null}
        //   E:X – {"error": {"class": "X", ...}}     error, class X
        //   V:X – {... "event": "X" ...}             async event X
        //
        // The sorted multiset of these tokens is hashed. This caps the distinct-hash space
        // to roughly O(N^K) where N≈10 token types and K = command count, yielding a
        // practical corpus of ~10K–50K instead of 10M+. The tokens are order-independent
        // (sorted) and content-independent (only shape matters), making the hash fully
        // deterministic even for commands with non-deterministic response content such as
        // query-cpus-fast (thread-id) or info mtree (address space ordering).
        let mut tokens: Vec<&'static str> = Vec::with_capacity(32);
        for line in stdout.split(|&b| b == b'\n') {
            if line.is_empty() || line.starts_with(b"{\"QMP\"") {
                continue;
            }
            let tok = qmp_response_token(line);
            if !tok.is_empty() {
                tokens.push(tok);
            }
        }
        tokens.sort_unstable();
        let mut hasher = DefaultHasher::new();
        tokens.hash(&mut hasher);
        self.hash = Some(hasher.finish());
    }
}

/// Classify one QMP output line into a short stable token used for corpus deduplication.
///
/// Returning a `&'static str` for the common cases avoids allocation in the hot path.
/// Caller must handle the owned `String` variants (E: and V: prefixes) separately if
/// distinct error/event classes are needed — but since we use a sorted token list that is
/// immediately hashed, we store interned literals for the known classes and fall back to
/// a fixed token for unknowns to keep this function allocation-free.
fn qmp_response_token(line: &[u8]) -> &'static str {
    // Success responses
    if line.starts_with(b"{\"return\":") || line.starts_with(b"{\"return\": ") {
        let val_start = if let Some(p) = find_bytes(line, b": ") { p + 2 } else { 10 };
        let rest = &line[val_start.min(line.len())..];
        if rest.starts_with(b"{}") || rest.starts_with(b"{ }") || rest.starts_with(b"[]}") {
            return "R0";
        }
        if rest.starts_with(b"[]") {
            return "R0";  // empty array ≡ empty return for our purposes
        }
        if rest.starts_with(b"[") {
            return "RA";
        }
        if rest.starts_with(b"\"") {
            return "RS";
        }
        if rest.starts_with(b"null") {
            return "RN";
        }
        if rest.starts_with(b"true") || rest.starts_with(b"false") {
            return "RB";
        }
        if rest.starts_with(b"{") {
            return "RO";
        }
        return "R?";
    }

    // Error responses – classify by error class for fine-grained guidance
    if find_bytes(line, b"\"class\":\"").is_some() {
        if find_bytes(line, b"DeviceNotFound").is_some() { return "E:DeviceNotFound"; }
        if find_bytes(line, b"GenericError").is_some()   { return "E:GenericError"; }
        if find_bytes(line, b"CommandNotFound").is_some(){ return "E:CommandNotFound"; }
        if find_bytes(line, b"KVMMissingCap").is_some()  { return "E:KVMMissingCap"; }
        return "E:Other";
    }

    // Async events – classify by event name
    if find_bytes(line, b"\"event\":\"").is_some() {
        if find_bytes(line, b"SHUTDOWN").is_some()        { return "V:SHUTDOWN"; }
        if find_bytes(line, b"RESET").is_some()           { return "V:RESET"; }
        if find_bytes(line, b"DEVICE_DELETED").is_some()  { return "V:DEVICE_DELETED"; }
        if find_bytes(line, b"SUSPEND").is_some()         { return "V:SUSPEND"; }
        if find_bytes(line, b"WAKEUP").is_some()          { return "V:WAKEUP"; }
        return "V:Other";
    }

    ""
}

/// Return the byte offset of the first occurrence of `needle` in `haystack`, or `None`.
#[inline]
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Strips the non-deterministic numeric values from QEMU QMP timestamp fields so
/// that the same logical execution always produces the same stdout hash.
///
/// QEMU emits events like:
///   {"event":"SHUTDOWN","timestamp":{"seconds":1772808637,"microseconds":975681},...}
/// The seconds/microseconds values differ on every run, causing every stdout to
/// hash differently and every input to be added to the corpus (19 GB of noise in
/// 12 h of fuzzing).  We replace those digit sequences with the literal `0`.
fn normalize_qemu_stdout(stdout: &[u8]) -> Vec<u8> {
    // Patterns followed by optional whitespace then a digit sequence.
    // Used for JSON timestamp fields: "seconds": 12345 → "seconds": 0
    const SPACED_PATTERNS: &[&[u8]] = &[b"\"seconds\":", b"\"microseconds\":", b"\"thread-id\":"];

    // Patterns that must be immediately followed by at least one digit (no separator).
    // Only normalised when a digit is actually present, preventing false matches on
    // words like "'device'" that share a prefix with "'dev<NNN>'".
    //   "#netNNN"   – internal netdev counter in `hmp info network` output
    //   "'devNNN'"  – device ID echoed back in DeviceNotFound error messages
    //   "'objNNN'"  – object ID echoed back in object-not-found error messages
    //   "'hnetNNN'" – hotplugged netdev ID in DeviceNotFound errors
    //   "thread_id=" – CPU thread ID from `hmp info cpus`, varies per QEMU process
    const DIRECT_PATTERNS: &[&[u8]] = &[b"#net", b"'dev", b"'obj", b"'hnet", b"'chr", b"='blk", b"thread_id="];

    let mut out = Vec::with_capacity(stdout.len());
    let mut i = 0;
    'byte: while i < stdout.len() {
        for pat in SPACED_PATTERNS {
            if stdout[i..].starts_with(pat) {
                out.extend_from_slice(pat);
                i += pat.len();
                while i < stdout.len() && stdout[i] == b' ' {
                    out.push(stdout[i]);
                    i += 1;
                }
                while i < stdout.len() && stdout[i].is_ascii_digit() {
                    i += 1;
                }
                out.push(b'0');
                continue 'byte;
            }
        }
        for pat in DIRECT_PATTERNS {
            if stdout[i..].starts_with(pat) {
                let digits_start = i + pat.len();
                let mut j = digits_start;
                while j < stdout.len() && stdout[j].is_ascii_digit() {
                    j += 1;
                }
                // Only normalise when at least one digit follows the prefix.
                if j > digits_start {
                    out.extend_from_slice(pat);
                    out.push(b'0');
                    i = j;
                    continue 'byte;
                }
            }
        }
        out.push(stdout[i]);
        i += 1;
    }
    out
}

/// Build the base QEMU command shared by both the fuzzer executor and the replay harness.
/// The caller is responsible for setting `.stdout(...)` as appropriate (piped for the
/// executor, null for standalone replay).
fn build_base_qemu_command(qemu_bin: &Path, machine: &str, debug: bool) -> Command {
    let mut cmd = Command::new(qemu_bin);
    cmd.arg("-machine")
        .arg(machine)
        .arg("-m")
        .arg("64m")
        .arg("-smp")
        .arg("1")
        .arg("-display")
        .arg("none")
        .arg("-monitor")
        .arg("none")
        .arg("-serial")
        .arg("none")
        // Prevent QEMU from looping on guest reboot/reset events; it must exit instead.
        .arg("-no-reboot")
        // USB controller: required for usb-mouse, usb-kbd, usb-tablet hotplug.
        .arg("-device")
        .arg("ich9-usb-uhci1,id=usb0")
        .arg("-qmp")
        .arg("stdio")
        .stdin(Stdio::piped());

    if debug {
        cmd.stderr(Stdio::inherit());
    } else {
        cmd.stderr(Stdio::null());
    }
    cmd
}

fn push_exec(cmds: &mut String, exec: &str) {
    cmds.push_str("{\"execute\":\"");
    cmds.push_str(exec);
    cmds.push_str("\"}\n");
}

fn push_hmp(cmds: &mut String, hmp: &str) {
    cmds.push_str("{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"");
    cmds.push_str(hmp);
    cmds.push_str("\"}}\n");
}

fn push_device_add(cmds: &mut String, driver: &str, id: &str) {
    cmds.push_str("{\"execute\":\"device_add\",\"arguments\":{\"driver\":\"");
    cmds.push_str(driver);
    cmds.push_str("\",\"id\":\"");
    cmds.push_str(id);
    cmds.push_str("\"}}\n");
}

fn push_device_del(cmds: &mut String, id: &str) {
    cmds.push_str("{\"execute\":\"device_del\",\"arguments\":{\"id\":\"");
    cmds.push_str(id);
    cmds.push_str("\"}}\n");
}

fn push_object_add(cmds: &mut String, qom_type: &str, id: &str, size_mb: u64) {
    match qom_type {
        "memory-backend-ram" => {
            cmds.push_str("{\"execute\":\"object-add\",\"arguments\":{\"qom-type\":\"");
            cmds.push_str(qom_type);
            cmds.push_str("\",\"id\":\"");
            cmds.push_str(id);
            cmds.push_str("\",\"size\":");
            cmds.push_str(&(size_mb.saturating_mul(1024 * 1024)).to_string());
            cmds.push_str("}}\n");
        }
        _ => {
            cmds.push_str("{\"execute\":\"object-add\",\"arguments\":{\"qom-type\":\"");
            cmds.push_str(qom_type);
            cmds.push_str("\",\"id\":\"");
            cmds.push_str(id);
            cmds.push_str("\"}}\n");
        }
    }
}

fn push_object_del(cmds: &mut String, id: &str) {
    cmds.push_str("{\"execute\":\"object-del\",\"arguments\":{\"id\":\"");
    cmds.push_str(id);
    cmds.push_str("\"}}\n");
}

fn push_qom_list(cmds: &mut String, path: &str) {
    cmds.push_str("{\"execute\":\"qom-list\",\"arguments\":{\"path\":\"");
    cmds.push_str(path);
    cmds.push_str("\"}}\n");
}

fn push_qom_get(cmds: &mut String, path: &str, property: &str) {
    cmds.push_str("{\"execute\":\"qom-get\",\"arguments\":{\"path\":\"");
    cmds.push_str(path);
    cmds.push_str("\",\"property\":\"");
    cmds.push_str(property);
    cmds.push_str("\"}}\n");
}

/// qom-set: write a value to a writable QOM property.
/// Most "set" attempts will return GenericError (read-only or wrong type), but
/// writable numeric/bool/string properties can trigger deep property-setter code
/// paths that are not exercised by read-only fuzzing.
fn push_qom_set(cmds: &mut String, path: &str, property: &str, value: &str) {
    cmds.push_str("{\"execute\":\"qom-set\",\"arguments\":{\"path\":\"");
    cmds.push_str(path);
    cmds.push_str("\",\"property\":\"");
    cmds.push_str(property);
    cmds.push_str("\",\"value\":");
    cmds.push_str(value);
    cmds.push_str("}}\n");
}

fn push_query_cmdline_options(cmds: &mut String, option: &str) {
    cmds.push_str("{\"execute\":\"query-command-line-options\",\"arguments\":{\"option\":\"");
    cmds.push_str(option);
    cmds.push_str("\"}}\n");
}

fn push_device_list_properties(cmds: &mut String, driver: &str) {
    cmds.push_str("{\"execute\":\"device-list-properties\",\"arguments\":{\"typename\":\"");
    cmds.push_str(driver);
    cmds.push_str("\"}}\n");
}

fn push_netdev_add(cmds: &mut String, id: &str) {
    cmds.push_str("{\"execute\":\"netdev_add\",\"arguments\":{\"type\":\"user\",\"id\":\"");
    cmds.push_str(id);
    cmds.push_str("\"}}\n");
}

fn push_netdev_del(cmds: &mut String, id: &str) {
    cmds.push_str("{\"execute\":\"netdev_del\",\"arguments\":{\"id\":\"");
    cmds.push_str(id);
    cmds.push_str("\"}}\n");
}

fn push_chardev_add(cmds: &mut String, backend: &str, id: &str) {
    cmds.push_str("{\"execute\":\"chardev-add\",\"arguments\":{\"id\":\"");
    cmds.push_str(id);
    cmds.push_str("\",\"backend\":{\"type\":\"");
    cmds.push_str(backend);
    cmds.push_str("\",\"data\":{}}}}\n");
}

fn push_chardev_remove(cmds: &mut String, id: &str) {
    cmds.push_str("{\"execute\":\"chardev-remove\",\"arguments\":{\"id\":\"");
    cmds.push_str(id);
    cmds.push_str("\"}}\n");
}

fn push_blockdev_add(cmds: &mut String, node_name: &str) {
    cmds.push_str("{\"execute\":\"blockdev-add\",\"arguments\":{\"driver\":\"null-co\",\"node-name\":\"");
    cmds.push_str(node_name);
    cmds.push_str("\"}}\n");
}

fn push_blockdev_del(cmds: &mut String, node_name: &str) {
    cmds.push_str("{\"execute\":\"blockdev-del\",\"arguments\":{\"node-name\":\"");
    cmds.push_str(node_name);
    cmds.push_str("\"}}\n");
}

/// Op 24: send-key — deliver a single key (qcode) to the guest keyboard controller.
/// Exercises the i8042 PS/2 KBC scancode translation path, SeaBIOS IRQ-1 handler,
/// and ACPI warm-reset on ctrl-alt-delete.
fn push_send_key(cmds: &mut String, key: &str) {
    cmds.push_str(
        "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"",
    );
    cmds.push_str(key);
    cmds.push_str("\"}]}}\n");
}

/// Op 25: mouse_move — deliver relative pointer motion via the HMP monitor.
/// Exercises PS/2 AUX-port mouse emulation and USB tablet absolute-position logic.
fn push_mouse_move(cmds: &mut String, dx: i8, dy: i8) {
    cmds.push_str("{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"mouse_move ");
    cmds.push_str(&dx.to_string());
    cmds.push(' ');
    cmds.push_str(&dy.to_string());
    cmds.push_str("\"}}\n");
}

/// Op 25b: mouse_button — emits a mouse button press/release.
fn push_mouse_button(cmds: &mut String, button_mask: u8) {
    cmds.push_str("{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"mouse_button ");
    cmds.push_str(&button_mask.to_string());
    cmds.push_str("\"}}\n");
}

/// Op 26: screendump — requests a VGA framebuffer capture.
/// Exercises the VGA VRAM readout path and display backend.  Writing to /dev/null
/// avoids filling the disk.
fn push_screendump(cmds: &mut String) {
    cmds.push_str(
        "{\"execute\":\"screendump\",\"arguments\":{\"filename\":\"/dev/null\"}}\n",
    );
}

// Op 18: memory balloon – request the guest to surrender/claim memory.
fn push_balloon(cmds: &mut String, value_mb: u64) {
    let value_bytes = value_mb.saturating_mul(1024 * 1024);
    cmds.push_str("{\"execute\":\"balloon\",\"arguments\":{\"value\":");
    cmds.push_str(&value_bytes.to_string());
    cmds.push_str("}}\n");
}

// Op 21: set-action – configure QEMU's response to VM lifecycle events.
// Setting "shutdown":"ignore" keeps QEMU alive after a guest poweroff attempt,
// "pause" leaves the VM paused instead of exiting.  Interesting because it
// changes the state machine that device hotplug and reset interact with.
fn push_set_action(cmds: &mut String, shutdown: &str, reboot: &str, panic: &str) {
    cmds.push_str("{\"execute\":\"set-action\",\"arguments\":{\"shutdown\":\"");
    cmds.push_str(shutdown);
    cmds.push_str("\",\"reboot\":\"");
    cmds.push_str(reboot);
    cmds.push_str("\",\"panic\":\"");
    cmds.push_str(panic);
    cmds.push_str("\"}}\n");
}

// Op 22: migrate-set-parameters – fuzz the live-migration engine configuration.
// Many parameters interact with memory/bandwidth limits; extreme values (0, MAX)
// can expose integer overflow and unchecked-arithmetic bugs in migration code.
fn push_migrate_set_parameters(cmds: &mut String, key: &str, value: &str) {
    cmds.push_str("{\"execute\":\"migrate-set-parameters\",\"arguments\":{\"");
    cmds.push_str(key);
    cmds.push_str("\":");
    cmds.push_str(value);
    cmds.push_str("}}\n");
}

// Op 23: migrate-set-capabilities – toggle individual migration capability flags.
fn push_migrate_set_capabilities(cmds: &mut String, cap: &str, state: bool) {
    cmds.push_str(
        "{\"execute\":\"migrate-set-capabilities\",\"arguments\":{\"capabilities\":[{\"capability\":\"",
    );
    cmds.push_str(cap);
    cmds.push_str(if state {
        "\",\"state\":true}]}}\n"
    } else {
        "\",\"state\":false}]}}\n"
    });
}

// ── Chunk-aware mutators ──────────────────────────────────────────────────────
//
// The fuzzer input is a sequence of 4-byte chunks:
//   b0: operation selector  (op = b0 % 12)
//   b1: argument 1          (selects from QUERY_COMMANDS, DEVICE_DRIVERS, …)
//   b2: argument 2          (size, secondary selector)
//   b3: argument 3          (binary flag for some ops)
//
// Generic byte-level havoc mutations can corrupt chunk alignment, so we add two
// mutators that understand the structure.

/// Mutates one argument byte (b1, b2, or b3) within a randomly chosen chunk
/// while leaving the operation selector (b0) intact.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ChunkArgMutator;

impl Named for ChunkArgMutator {
    fn name(&self) -> &str {
        "ChunkArgMutator"
    }
}

impl<I, S> Mutator<I, S> for ChunkArgMutator
where
    I: HasBytesVec,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let bytes = input.bytes_mut();
        if bytes.len() < 2 {
            return Ok(MutationResult::Skipped);
        }
        // 75 % of all byte positions are argument bytes (offset != 0 in chunk).
        // Up to 8 retries gives a >99.998 % success rate even for short inputs.
        for _ in 0..8 {
            let idx = state.rand_mut().below(bytes.len() as u64) as usize;
            if idx % 4 != 0 {
                bytes[idx] = state.rand_mut().below(256) as u8;
                return Ok(MutationResult::Mutated);
            }
        }
        Ok(MutationResult::Skipped)
    }
}

/// Mutates the operation-selector byte (b0) of a randomly chosen chunk,
/// replacing it with a direct op index (0–11) to guarantee a valid operation.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ChunkOpMutator;

impl Named for ChunkOpMutator {
    fn name(&self) -> &str {
        "ChunkOpMutator"
    }
}

impl<I, S> Mutator<I, S> for ChunkOpMutator
where
    I: HasBytesVec,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let bytes = input.bytes_mut();
        if bytes.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let num_chunks = (bytes.len() + 3) / 4;
        let byte_idx = state.rand_mut().below(num_chunks as u64) as usize * 4;
        if byte_idx >= bytes.len() {
            return Ok(MutationResult::Skipped);
        }
        // Write a direct op index so b0 % 28 lands exactly on the chosen op.
        bytes[byte_idx] = state.rand_mut().below(28) as u8;
        Ok(MutationResult::Mutated)
    }
}

/// Trims the input to a random multiple of 4 bytes no longer than `max_commands * 4`.
///
/// AFL/LibAFL havoc mutators (splice, crossover) produce ever-growing inputs over time.
/// Bytes past `max_commands * 4` are silently ignored during execution, so long inputs
/// generate the same response as their prefix — but they get stored as distinct corpus
/// entries (different bytes → different de-dup key). This mutator fights corpus bloat by
/// periodically shrinking inputs back to an effective length.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ChunkTrimMutator {
    max_commands: usize,
}

impl ChunkTrimMutator {
    fn new(max_commands: usize) -> Self {
        Self { max_commands }
    }
}

impl Named for ChunkTrimMutator {
    fn name(&self) -> &str {
        "ChunkTrimMutator"
    }
}

impl<I, S> Mutator<I, S> for ChunkTrimMutator
where
    I: HasBytesVec,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let bytes = input.bytes_mut();
        let max_bytes = self.max_commands * 4;
        // Only act if the input exceeds the useful cap, or stochastically (10% chance)
        // shrink to a shorter valid prefix to encourage focused short sequences.
        let do_trim = bytes.len() > max_bytes
            || (bytes.len() > 4 && state.rand_mut().below(10) == 0);
        if !do_trim {
            return Ok(MutationResult::Skipped);
        }
        // Choose a new length: a random multiple of 4 in [4, effective_max].
        let effective_max = bytes.len().min(max_bytes);
        let num_chunks = (effective_max / 4).max(1);
        let new_chunks = 1 + state.rand_mut().below(num_chunks as u64) as usize;
        let new_len = new_chunks * 4;
        if new_len >= bytes.len() {
            return Ok(MutationResult::Skipped);
        }
        bytes.truncate(new_len);
        Ok(MutationResult::Mutated)
    }
}

/// Build a QMP command sequence from the raw fuzzer `data` bytes.
///
/// When `persistent` is **true** the trailing `quit` command is omitted.
/// The caller is responsible for appending a sentinel (e.g. `query-version`)
/// and detecting the end of the testcase via the sentinel response.
fn qmp_program_from_bytes(data: &[u8], max_commands: usize, persistent: bool) -> Vec<u8> {
    let mut cmds = String::with_capacity(1024);
    let mut next_device_id: u64 = 0;
    let mut next_object_id: u64 = 0;
    let mut next_netdev_id: u64 = 0;
    let mut next_chardev_id: u64 = 0;
    let mut next_blockdev_id: u64 = 0;
    let mut live_devices: Vec<String> = Vec::new();
    let mut live_objects: Vec<String> = Vec::new();
    let mut live_netdevs: Vec<String> = Vec::new();
    let mut live_chardevs: Vec<String> = Vec::new();
    let mut live_blockdevs: Vec<String> = Vec::new();
    // Track whether the VM is currently paused so we only send `cont` in
    // cleanup when actually needed.  Sending `cont` to a running VM returns
    // an error response that pollutes the stdout hash and inflates the corpus.
    let mut vm_paused = false;

    push_exec(&mut cmds, "qmp_capabilities");
    // Note: query-commands is intentionally omitted from the preamble.
    // It produces a ~5 KB constant JSON blob per execution (wasting pipe bandwidth)
    // and is already reachable via op=0 (QUERY_COMMANDS[] includes "query-commands").

    for chunk in data.chunks(4).take(max_commands) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let b3 = chunk.get(3).copied().unwrap_or(0);
        let op = b0 % 28;

        match op {
            0 => {
                let query = QUERY_COMMANDS[(b1 as usize) % QUERY_COMMANDS.len()];
                push_exec(&mut cmds, query);
            }
            1 => {
                let hmp = HMP_COMMANDS[(b1 as usize) % HMP_COMMANDS.len()];
                push_hmp(&mut cmds, hmp);
            }
            2 => {
                let driver = DEVICE_DRIVERS[(b1 as usize) % DEVICE_DRIVERS.len()];
                let id = format!("dev{next_device_id}");
                next_device_id += 1;
                push_device_add(&mut cmds, driver, &id);
                live_devices.push(id);
            }
            3 => {
                if live_devices.is_empty() {
                    push_exec(&mut cmds, "query-status");
                } else {
                    let pick = (b1 as usize) % live_devices.len();
                    let id = live_devices.swap_remove(pick);
                    push_device_del(&mut cmds, &id);
                }
            }
            4 => {
                let path = QOM_PATHS[(b1 as usize) % QOM_PATHS.len()];
                push_qom_list(&mut cmds, path);
            }
            5 => {
                let option = CMDLINE_OPTIONS[(b1 as usize) % CMDLINE_OPTIONS.len()];
                push_query_cmdline_options(&mut cmds, option);
            }
            6 => {
                let qom_type = OBJECT_TYPES[(b1 as usize) % OBJECT_TYPES.len()];
                let id = format!("obj{next_object_id}");
                next_object_id += 1;
                let size_mb = ((b2 as u64) % 64) + 1;
                push_object_add(&mut cmds, qom_type, &id, size_mb);
                live_objects.push(id);
            }
            7 => {
                if live_objects.is_empty() {
                    push_exec(&mut cmds, "query-status");
                } else {
                    let pick = (b1 as usize) % live_objects.len();
                    let id = live_objects.swap_remove(pick);
                    push_object_del(&mut cmds, &id);
                }
            }
            8 => {
                let path = QOM_PATHS[(b1 as usize) % QOM_PATHS.len()];
                let property = QOM_PROPERTIES[(b2 as usize) % QOM_PROPERTIES.len()];
                push_qom_get(&mut cmds, path, property);
            }
            9 => {
                if b1 & 0x1 == 0 {
                    push_exec(&mut cmds, "stop");
                    vm_paused = true;
                } else {
                    push_exec(&mut cmds, "cont");
                    vm_paused = false;
                }
                if b2 & 0x1 == 0 {
                    push_exec(&mut cmds, "query-status");
                }
            }
            10 => {
                let driver = DEVICE_DRIVERS[(b1 as usize) % DEVICE_DRIVERS.len()];
                push_device_list_properties(&mut cmds, driver);
            }
            11 => {
                if b3 & 0x1 == 0 {
                    push_exec(&mut cmds, "qom-list-types");
                } else {
                    push_exec(&mut cmds, "query-memory-size-summary");
                }
            }
            12 => {
                // netdev_add (user-mode) or netdev_del if live netdevs exist.
                if b1 & 0x1 == 0 || live_netdevs.is_empty() {
                    let id = format!("hnet{next_netdev_id}");
                    next_netdev_id += 1;
                    push_netdev_add(&mut cmds, &id);
                    live_netdevs.push(id);
                } else {
                    let pick = (b2 as usize) % live_netdevs.len();
                    let id = live_netdevs.swap_remove(pick);
                    push_netdev_del(&mut cmds, &id);
                }
            }
            13 => {
                // chardev-add or chardev-remove if live chardevs exist.
                if b1 & 0x1 == 0 || live_chardevs.is_empty() {
                    let backend = CHARDEV_BACKENDS[(b2 as usize) % CHARDEV_BACKENDS.len()];
                    let id = format!("chr{next_chardev_id}");
                    next_chardev_id += 1;
                    push_chardev_add(&mut cmds, backend, &id);
                    live_chardevs.push(id);
                } else {
                    let pick = (b2 as usize) % live_chardevs.len();
                    let id = live_chardevs.swap_remove(pick);
                    push_chardev_remove(&mut cmds, &id);
                }
            }
            14 => {
                // blockdev-add (null-co) or blockdev-del if live blockdevs exist.
                if b1 & 0x1 == 0 || live_blockdevs.is_empty() {
                    let node_name = format!("blk{next_blockdev_id}");
                    next_blockdev_id += 1;
                    push_blockdev_add(&mut cmds, &node_name);
                    live_blockdevs.push(node_name);
                } else {
                    let pick = (b2 as usize) % live_blockdevs.len();
                    let node_name = live_blockdevs.swap_remove(pick);
                    push_blockdev_del(&mut cmds, &node_name);
                }
            }
            15 => {
                // Op 15: extended HMP commands that probe CPU / memory state.
                // "info registers" is excluded: SeaBIOS executes concurrently so CPU
                // register values differ on every run, making that output non-deterministic.
                // "info chardev" is excluded: it would expose the dynamic chr{N} IDs
                // in unquoted form (chr0: filename=...) which the normaliser can't strip.
                const EXTENDED_HMP: &[&str] =
                    &["info cpus", "info mem", "info blockstats", "info lapic"];
                let hmp = EXTENDED_HMP[(b1 as usize) % EXTENDED_HMP.len()];
                push_hmp(&mut cmds, hmp);
            }
            16 => {
                // Op 16: system_reset — sends a hard machine reset via QMP.
                // In persistent mode, system_reset causes QEMU to exit(0) via -no-reboot,
                // ending the session prematurely.  Across 8 workers and 28 ops, op 16
                // fires in ~27% of testcases (1 - (27/28)^9), so persistent sessions
                // average only ~4 testcases before QEMU is killed.  The resulting high
                // session-restart rate causes divergent QEMU state across sessions, which
                // in turn produces an enormous number of unique response hashes and blows
                // up the corpus (9M+ files).  In non-persistent mode the worker restarts
                // QEMU for every testcase anyway, so system_reset IS still exercised.
                if persistent {
                    push_exec(&mut cmds, "query-status");
                } else {
                    push_exec(&mut cmds, "system_reset");
                }
            }
            17 => {
                // Op 17: qom-set — write a value to a QOM property.
                // Most properties are read-only → E:GenericError, but writable
                // properties (e.g., balloon target, virtio queues, memory sizes)
                // invoke property-setter code paths with minimal test coverage.
                // Fuzzing setter inputs (bool/int/string) can expose type confusion
                // and boundary errors in QEMU device models.
                const QOM_SET_VALUES: &[&str] = &[
                    "true", "false", "0", "1", "255", "65535", "4294967295",
                    "\"\"", "\"x\"", "null",
                ];
                let path = QOM_PATHS[(b1 as usize) % QOM_PATHS.len()];
                let property = QOM_PROPERTIES[(b2 as usize) % QOM_PROPERTIES.len()];
                let value = QOM_SET_VALUES[(b3 as usize) % QOM_SET_VALUES.len()];
                push_qom_set(&mut cmds, path, property, value);
            }
            18 => {
                // Op 18: balloon / query-balloon — exercise the memory balloon driver.
                // balloon changes the guest-visible RAM target (requires virtio-balloon-pci).
                // Without the device QEMU returns GenericError (still exercises that path).
                // Extreme values (0, 4 GB) stress balloon-driver arithmetic.
                if b3 & 1 == 0 {
                    let size_mb = BALLOON_SIZES_MB[(b1 as usize) % BALLOON_SIZES_MB.len()];
                    push_balloon(&mut cmds, size_mb);
                } else {
                    push_exec(&mut cmds, "query-balloon");
                }
            }
            19 => {
                // Op 19: system_powerdown — sends ACPI power-button press to the guest.
                // Without an OS/ACPI-handler the guest ignores it; QEMU stays running.
                // Combined with device hotplug this exercises the ACPI interrupt delivery
                // path in QEMU's piix4-pm and ich9 device models.
                push_exec(&mut cmds, "system_powerdown");
            }
            20 => {
                // Op 20: inject-nmi — delivers a Non-Maskable Interrupt to all vCPUs.
                // The bare-metal guest (SeaBIOS) has no NMI handler, so the CPU triple-faults,
                // which requests a machine reset.  With -no-reboot QEMU converts that reset
                // into a shutdown and exits with code 0.  This makes inject-nmi equivalent
                // to system_reset in terms of persistent-session impact: ~3.6% chance per
                // chunk that the session is terminated prematurely.
                // In persistent mode, replace with query-status to keep the session alive.
                if persistent {
                    push_exec(&mut cmds, "query-status");
                } else {
                    push_exec(&mut cmds, "inject-nmi");
                }
            }
            21 => {
                // Op 21: set-action — configures what QEMU does on VM lifecycle events.
                // Interesting combinations: "shutdown":"ignore" keeps QEMU alive after
                // a guest poweroff (interacts with system_powerdown / system_reset),
                // "reboot":"shutdown" converts resets into exits.
                let shutdown = SHUTDOWN_ACTIONS[(b1 as usize) % SHUTDOWN_ACTIONS.len()];
                let reboot   = REBOOT_ACTIONS  [(b2 as usize) % REBOOT_ACTIONS.len()];
                let panic    = PANIC_ACTIONS   [(b3 as usize) % PANIC_ACTIONS.len()];
                push_set_action(&mut cmds, shutdown, reboot, panic);
            }
            22 => {
                // Op 22: migrate-set-parameters — fuzz live-migration engine config.
                // Extreme values (0, UINT64_MAX) can expose integer-overflow and
                // unvalidated-input bugs in migration parameter handling code.
                let (key, val) = MIGRATE_PARAMS[(b1 as usize) % MIGRATE_PARAMS.len()];
                push_migrate_set_parameters(&mut cmds, key, val);
            }
            23 => {
                // Op 23: migrate-set-capabilities — toggle individual migration flags.
                // Many capability combinations are not well tested; enabling rdma-pin-all
                // without RDMA hardware, or combining postcopy-ram + compression, can
                // expose assertion failures in capability negotiation code.
                let cap   = MIGRATE_CAPS[(b1 as usize) % MIGRATE_CAPS.len()];
                let state = b2 & 1 == 0;
                push_migrate_set_capabilities(&mut cmds, cap, state);
            }
            24 => {
                // Op 24: send-key — inject a key event into the guest PS/2 keyboard
                // controller (i8042).  Exercises IRQ-1 delivery, KBC scancode translation,
                // and SeaBIOS keyboard interrupt handler.  ctrl-alt-delete specifically
                // triggers a warm-reset path through the i8042 pulse-output-port mechanism.
                let key = SENDKEY_KEYS[(b1 as usize) % SENDKEY_KEYS.len()];
                push_send_key(&mut cmds, key);
            }
            25 => {
                // Op 25: mouse events — relative pointer motion and button press/release.
                // Exercises the PS/2 AUX-port emulation (i8042 command 0xD4) for mouse,
                // and USB tablet absolute-position logic (virtio-input, UHCI transfer rings).
                if b3 & 1 == 0 {
                    // Relative motion: dx and dy in [-64, 63]
                    let dx = (b1 as i8).wrapping_shr(1);
                    let dy = (b2 as i8).wrapping_shr(1);
                    push_mouse_move(&mut cmds, dx, dy);
                } else {
                    // Button: mask 0–7 (bits: left=1, middle=2, right=4)
                    let mask = b1 & 0x07;
                    push_mouse_button(&mut cmds, mask);
                }
            }
            26 => {
                // Op 26: screendump — read the VGA framebuffer and write to /dev/null.
                // Exercises the VGA VRAM readout path, the display surface blitting code,
                // and any registered DisplaySurface callback in the display backend.
                // Sending this repeatedly while hotplugging devices stresses concurrency
                // between the VGA display loop and device model tear-down.
                push_screendump(&mut cmds);
            }
            _ => {
                // Op 27: extended QMP queries — exercises additional QEMU subsystems.
                // Selects among several commands to avoid a single overloaded op:
                //   query-pci:  scans the PCI bus hierarchy → BDF enumeration code
                //   query-rx-filter: reads NIC receive filter tables → virtio-net code
                //   query-named-block-nodes: lists block layer graph → blk subsystem
                //   rtc-reset-reinjection: clears lost-tick counter → RTC/PIT code
                match b1 % 4 {
                    0 => push_exec(&mut cmds, "query-pci"),
                    1 => push_exec(&mut cmds, "query-rx-filter"),
                    2 => push_exec(&mut cmds, "query-named-block-nodes"),
                    _ => push_exec(&mut cmds, "rtc-reset-reinjection"),
                }
            }
        }
    }

    // Resume the VM before cleanup only if it was left in a paused state.
    if vm_paused {
        push_exec(&mut cmds, "cont");
    }
    for id in &live_devices {
        push_device_del(&mut cmds, id);
    }
    for id in &live_objects {
        push_object_del(&mut cmds, id);
    }
    for id in &live_netdevs {
        push_netdev_del(&mut cmds, id);
    }
    for id in &live_chardevs {
        push_chardev_remove(&mut cmds, id);
    }
    for node_name in &live_blockdevs {
        push_blockdev_del(&mut cmds, node_name);
    }
    if !persistent {
        push_exec(&mut cmds, "quit");
    }
    cmds.into_bytes()
}

// ── Persistent QMP executor ───────────────────────────────────────────────────
//
// Keeps a QEMU process alive across `session_length` testcases to amortise the
// per-process startup cost (~57 ms vanilla, ~1 400 ms ASan) over many runs.
//
// Protocol per testcase:
//   1. Build command payload (no `quit`) using `qmp_program_from_bytes(..., true)`.
//   2. Write payload + sentinel `{"execute":"query-version"}\n` to stdin.
//   3. Read lines until the sentinel response (`{"return":{"qemu":`) arrives.
//   4. Hash collected stdout via `observers.observe_stdout()`.
//   5. Restart session if QEMU exits early, times out, or session_length reached.
//
// QEMU crashes (non-zero exit) return `ExitKind::Crash` so LibAFL saves them.
// Clean early exits (exit 0, e.g., `-no-reboot` after guest reset) restart the
// session and return `ExitKind::Ok` so they are not saved as objectives.

/// Sentinel QMP command appended after each persistent testcase payload.
/// `query-version` returns `{"return":{"qemu":{...}}}` which contains the
/// unique substring `"qemu":` — not present in any other response.
const PERSISTENT_SENTINEL: &[u8] = b"{\"execute\":\"query-version\"}\n";

/// One running QEMU session used by `PersistentQmpExecutor`.
struct QmpSession {
    child: Child,
    stdin: io::BufWriter<ChildStdin>,
    /// Lines from QEMU stdout, sent by the reader thread.
    rx: mpsc::Receiver<io::Result<String>>,
}

impl QmpSession {
    /// Spawn a fresh QEMU process, perform the QMP handshake, and return a
    /// ready-to-use session.  Returns `Err` if QEMU fails to start or the
    /// initial greeting does not arrive within 10 seconds.
    fn start(qemu_bin: &Path, machine: &str, debug: bool) -> io::Result<Self> {
        let mut cmd = build_base_qemu_command(qemu_bin, machine, debug);
        cmd.stdout(Stdio::piped());
        let mut child = cmd.spawn()?;

        let stdout: ChildStdout = child.stdout.take().expect("stdout piped");
        let (tx, rx) = mpsc::channel::<io::Result<String>>();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let stdin_raw: ChildStdin = child.stdin.take().expect("stdin piped");
        let mut session = QmpSession {
            child,
            stdin: io::BufWriter::new(stdin_raw),
            rx,
        };

        // QMP handshake: wait for greeting, then send qmp_capabilities.
        session.drain_greeting(Duration::from_secs(10))?;
        Ok(session)
    }

    /// Consume lines from the reader thread until we see the `qmp_capabilities`
    /// success response `{"return": {}}`.  This primes the session.
    fn drain_greeting(&mut self, timeout: Duration) -> io::Result<()> {
        // Send qmp_capabilities immediately; the greeting line may arrive
        // concurrently — we just need to consume everything up to the first
        // `{"return"` which is the capabilities ACK.
        self.stdin.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
        self.stdin.flush()?;

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "QMP greeting timeout"));
            }
            match self.rx.recv_timeout(remaining) {
                Ok(Ok(line)) => {
                    if line.contains("\"return\"") {
                        return Ok(());
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "QMP greeting timeout"))
                }
            }
        }
    }

    /// Run one testcase: write `payload` + sentinel, collect stdout until the
    /// sentinel response, then return the raw stdout and exit kind.
    /// Poll the child until it exits (up to 2 s) and return the correct
    /// `ExitKind`.  Under heavy CPU load (10+ workers) QEMU can take 200-500 ms
    /// to finish cleanup after receiving a reset/shutdown signal; the old 150 ms
    /// deadline caused premature ExitKind::Crash for clean exit(0) cases.
    fn check_exit_status(&mut self) -> ExitKind {
        let deadline = Instant::now() + Duration::from_millis(2000);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    return if status.success() {
                        ExitKind::Ok
                    } else {
                        ExitKind::Crash
                    };
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        // Process hasn't exited after 2 s; treat as unexpected crash.
                        return ExitKind::Crash;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return ExitKind::Crash,
            }
        }
    }

    fn run_testcase(
        &mut self,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<(Vec<u8>, ExitKind)> {
        // Write the command payload (no `quit`) followed by the sentinel.
        if let Err(e) = self.stdin.write_all(payload) {
            if e.kind() != io::ErrorKind::BrokenPipe {
                return Err(e);
            }
            // BrokenPipe → QEMU has already exited; check the real exit code
            // so we don't misclassify a clean exit (e.g. system_reset / -no-reboot)
            // as a crash.
            return Ok((Vec::new(), self.check_exit_status()));
        }
        if let Err(e) = self.stdin.write_all(PERSISTENT_SENTINEL) {
            if e.kind() != io::ErrorKind::BrokenPipe {
                return Err(e);
            }
            return Ok((Vec::new(), self.check_exit_status()));
        }
        if let Err(e) = self.stdin.flush() {
            if e.kind() != io::ErrorKind::BrokenPipe {
                return Err(e);
            }
            return Ok((Vec::new(), self.check_exit_status()));
        }

        let mut stdout_buf: Vec<u8> = Vec::with_capacity(4096);
        let deadline = Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok((stdout_buf, ExitKind::Timeout));
            }
            match self.rx.recv_timeout(remaining) {
                Ok(Ok(line)) => {
                    stdout_buf.extend_from_slice(line.as_bytes());
                    stdout_buf.push(b'\n');
                    // `query-version` response always contains `"qemu":{` or `"qemu": {`
                    if find_bytes(line.as_bytes(), b"\"qemu\":{").is_some()
                        || find_bytes(line.as_bytes(), b"\"qemu\": {").is_some()
                    {
                        return Ok((stdout_buf, ExitKind::Ok));
                    }
                }
                Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // Reader thread terminated → QEMU process has exited.
                    // Wait briefly to ensure the exit status is available.
                    let exit_kind = self.check_exit_status();
                    return Ok((stdout_buf, exit_kind));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Ok((stdout_buf, ExitKind::Timeout));
                }
            }
        }
    }
}

impl Drop for QmpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A persistent LibAFL executor that reuses a single QEMU process across
/// multiple testcases.  Falls back to spawning a fresh process after
/// `session_length` executions, any crash, or any timeout.
pub struct PersistentQmpExecutor<OT, S> {
    qemu_bin: PathBuf,
    machine: String,
    timeout: Duration,
    max_commands: usize,
    session_length: usize,
    debug_child: bool,
    /// The currently running QEMU session (None if not yet started or after restart).
    session: Option<QmpSession>,
    /// How many testcases have been run in the current session.
    session_exec_count: usize,
    observers: OT,
    phantom: PhantomData<S>,
}

impl<OT, S> PersistentQmpExecutor<OT, S> {
    pub fn new(
        qemu_bin: PathBuf,
        machine: String,
        timeout: Duration,
        max_commands: usize,
        session_length: usize,
        debug_child: bool,
        observers: OT,
    ) -> Self {
        Self {
            qemu_bin,
            machine,
            timeout,
            max_commands,
            session_length,
            debug_child,
            session: None,
            session_exec_count: 0,
            observers,
            phantom: PhantomData,
        }
    }
}

impl<OT, S> fmt::Debug for PersistentQmpExecutor<OT, S>
where
    OT: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentQmpExecutor")
            .field("qemu_bin", &self.qemu_bin)
            .field("machine", &self.machine)
            .field("session_exec_count", &self.session_exec_count)
            .finish()
    }
}

impl<OT, S> UsesObservers for PersistentQmpExecutor<OT, S>
where
    OT: ObserversTuple<S>,
    S: State,
{
    type Observers = OT;
}

impl<OT, S> UsesState for PersistentQmpExecutor<OT, S>
where
    S: State,
{
    type State = S;
}

impl<OT, S> HasObservers for PersistentQmpExecutor<OT, S>
where
    OT: ObserversTuple<S>,
    S: State,
{
    fn observers(&self) -> &OT {
        &self.observers
    }
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<EM, OT, S, Z> Executor<EM, Z> for PersistentQmpExecutor<OT, S>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    OT: fmt::Debug + MatchName + ObserversTuple<S>,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &S::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        // Build the command payload without `quit`.
        let payload =
            qmp_program_from_bytes(input.target_bytes().as_slice(), self.max_commands, true);

        // Ensure a live session exists.
        if self.session.is_none() {
            match QmpSession::start(&self.qemu_bin, &self.machine, self.debug_child) {
                Ok(s) => {
                    self.session = Some(s);
                    self.session_exec_count = 0;
                }
                Err(e) => return Err(Error::unknown(e.to_string())),
            }
        }

        let (stdout_buf, exit_kind) = self
            .session
            .as_mut()
            .unwrap()
            .run_testcase(&payload, self.timeout)
            .unwrap_or_else(|_| (Vec::new(), ExitKind::Crash));

        // Feed collected output to observers (the StdOutHashObserver reads this).
        self.observers.observe_stdout(&stdout_buf);

        self.session_exec_count += 1;

        // Restart if we hit a crash/timeout, the session limit, or QEMU has
        // already exited on its own (e.g., system_reset with -no-reboot gives
        // exit code 0 — a clean exit that still invalidates the session).
        let qemu_already_gone = self
            .session
            .as_mut()
            .and_then(|s| s.child.try_wait().ok())
            .map(|opt| opt.is_some()) // Some(status) means process has exited
            .unwrap_or(true);

        if matches!(exit_kind, ExitKind::Crash | ExitKind::Timeout)
            || qemu_already_gone
            || self.session_exec_count >= self.session_length
        {
            self.session = None;
        }

        Ok(exit_kind)
    }
}

fn ensure_seed_corpus(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    if fs::read_dir(path)?.next().is_some() {
        return Ok(());
    }

    let seeds: [(&str, &[u8]); 44] = [
        ("seed-query.bin", &[0x00, 0x00, 0x00, 0x00]),
        ("seed-hmp.bin", &[0x01, 0x00, 0x00, 0x00]),
        ("seed-device-add.bin", &[0x02, 0x00, 0x00, 0x02, 0x01, 0x00]),
        (
            // chunk-1: op=2 (device_add, driver=e1000, id=dev0)
            // chunk-2: op=3 (device_del, pick=0 → dev0)
            // Exercises the in-loop device_del path (op=3) — now actually succeeds on pc.
            "seed-device-cycle.bin",
            &[0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00],
        ),
        ("seed-qom.bin", &[0x04, 0x00, 0x00]),
        ("seed-options.bin", &[0x05, 0x00, 0x00]),
        ("seed-object-add.bin", &[0x06, 0x00, 0x10, 0x00]),
        (
            "seed-object-cycle.bin",
            &[0x06, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00],
        ),
        ("seed-qom-get.bin", &[0x08, 0x00, 0x00, 0x00]),
        (
            "seed-stop-cont.bin",
            &[0x09, 0x00, 0x01, 0x00, 0x09, 0x01, 0x01, 0x00],
        ),
        ("seed-list-properties.bin", &[0x0a, 0x00, 0x00, 0x00]),
        ("seed-qom-types.bin", &[0x0b, 0x00, 0x00, 0x00]),
        // op=12: netdev_add (user)
        ("seed-netdev-add.bin", &[0x0c, 0x00, 0x00, 0x00]),
        // op=12 add then del: hnet0 add (b1=0→add) then hnet0 del (b1=1→del, b2=0→pick 0)
        (
            "seed-netdev-cycle.bin",
            &[0x0c, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00],
        ),
        // op=13: chardev-add null
        ("seed-chardev-add.bin", &[0x0d, 0x00, 0x00, 0x00]),
        // op=13 cycle: chardev null add then remove
        (
            "seed-chardev-cycle.bin",
            &[0x0d, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x00, 0x00],
        ),
        // op=14: blockdev-add null-co
        ("seed-blockdev-add.bin", &[0x0e, 0x00, 0x00, 0x00]),
        // op=14 cycle: blockdev add then del
        (
            "seed-blockdev-cycle.bin",
            &[0x0e, 0x00, 0x00, 0x00, 0x0e, 0x01, 0x00, 0x00],
        ),
        // op=15: extended HMP (info cpus)
        ("seed-ext-hmp.bin", &[0x0f, 0x00, 0x00, 0x00]),
        // op=16: system_reset (standalone reset)
        ("seed-system-reset.bin", &[0x10, 0x00, 0x00, 0x00]),
        // op=16: device_add then system_reset then device_del (reset-path stress)
        (
            "seed-reset-with-device.bin",
            &[0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00],
        ),
        // op=17: qom-set /machine realized=true  b0=17 b1=0(/machine) b2=2(realized) b3=0(true)
        ("seed-qom-set.bin", &[0x11, 0x00, 0x02, 0x00]),
        // op=17: qom-set with int value 0
        ("seed-qom-set-int.bin", &[0x11, 0x00, 0x00, 0x04]),
        // op=18: balloon 64MB  b0=18 b1=1(64MB) b3=0(set not query)
        ("seed-balloon.bin", &[0x12, 0x01, 0x00, 0x00]),
        // op=18: query-balloon  b3=1 → query path
        ("seed-query-balloon.bin", &[0x12, 0x00, 0x00, 0x01]),
        // op=19: system_powerdown
        ("seed-powerdown.bin", &[0x13, 0x00, 0x00, 0x00]),
        // op=20: inject-nmi
        ("seed-inject-nmi.bin", &[0x14, 0x00, 0x00, 0x00]),
        // op=21: set-action shutdown=pause,reboot=reset,panic=none
        // b0=21(0x15) b1=1(pause) b2=0(reset) b3=2(none)
        ("seed-set-action.bin", &[0x15, 0x01, 0x00, 0x02]),
        // op=22: migrate-set-parameters max-bandwidth=0  b0=22(0x16) b1=0
        ("seed-migrate-params.bin", &[0x16, 0x00, 0x00, 0x00]),
        // op=23: migrate-set-capabilities xbzrle=false  b0=23(0x17) b1=0 b2=1(false)
        ("seed-migrate-caps.bin", &[0x17, 0x00, 0x01, 0x00]),
        // Scenario: device_add → qom-get → stop → system_reset → device_del
        // Tests the full device lifecycle across a machine reset (UAF / re-init bugs).
        (
            "seed-scenario-reset-uaf.bin",
            &[
                0x02, 0x00, 0x00, 0x00, // op=2:  device_add(e1000, dev0)
                0x08, 0x00, 0x01, 0x00, // op=8:  qom-get(/machine, power0)
                0x09, 0x00, 0x01, 0x00, // op=9:  stop + query-status
                0x10, 0x00, 0x00, 0x00, // op=16: system_reset
                0x03, 0x00, 0x00, 0x00, // op=3:  device_del(dev0) — post-reset
            ],
        ),
        // Scenario: set-action(shutdown=ignore) → system_powerdown → inject-nmi
        // Tests ACPI + NMI delivery with custom shutdown policy (shutdown must be ignored
        // so QEMU stays alive after system_powerdown, allowing inject-nmi to follow).
        (
            "seed-scenario-acpi-nmi.bin",
            &[
                0x15, 0x00, 0x00, 0x00, // op=21: set-action(shutdown=poweroff,reboot=reset,panic=shutdown)
                0x13, 0x00, 0x00, 0x00, // op=19: system_powerdown
                0x14, 0x00, 0x00, 0x00, // op=20: inject-nmi
            ],
        ),
        // Scenario: multiple device_add → system_reset → device_del all
        // Tests bulk device state cleanup after reset.  Variant with 3 different drivers.
        (
            "seed-scenario-multi-device-reset.bin",
            &[
                0x02, 0x00, 0x00, 0x00, // op=2: device_add(e1000)
                0x02, 0x03, 0x00, 0x00, // op=2: device_add(rtl8139)
                0x02, 0x06, 0x00, 0x00, // op=2: device_add(virtio-net-pci)
                0x10, 0x00, 0x00, 0x00, // op=16: system_reset
                0x03, 0x00, 0x00, 0x00, // op=3:  device_del(0)
                0x03, 0x00, 0x00, 0x00, // op=3:  device_del(1)
                0x03, 0x00, 0x00, 0x00, // op=3:  device_del(2)
            ],
        ),
        // Scenario: migrate-set-parameters + migrate-set-capabilities + query-migrate
        // Tests migration engine config paths.  query-migrate returns "completed"/"idle".
        (
            "seed-scenario-migrate-config.bin",
            &[
                0x16, 0x00, 0x00, 0x00, // op=22: migrate-set-parameters(max-bandwidth=0)
                0x16, 0x07, 0x00, 0x00, // op=22: migrate-set-parameters(max-cpu-throttle=0)
                0x17, 0x00, 0x00, 0x00, // op=23: migrate-set-capabilities(xbzrle=true)
                0x00, 0x09, 0x00, 0x00, // op=0:  QUERY_COMMANDS[9] = query-migrate
            ],
        ),
        // Scenario: object_add → balloon → qom-set on object → object_del
        // Tests memory balloon interaction with QOM object lifecycle.
        (
            "seed-scenario-balloon-object.bin",
            &[
                0x06, 0x00, 0x08, 0x00, // op=6: object-add(memory-backend-ram, 8MB)
                0x12, 0x01, 0x00, 0x00, // op=18: balloon(64MB)
                0x12, 0x00, 0x00, 0x01, // op=18: query-balloon
                0x07, 0x00, 0x00, 0x00, // op=7: object-del(obj0)
            ],
        ),
        // ── New ops 24-27 ──────────────────────────────────────────────────────
        // op=24: send-key(ret) — press Enter, exercises i8042 KBC + SeaBIOS IRQ-1
        ("seed-sendkey-ret.bin",    &[0x18, 0x00, 0x00, 0x00]),
        // op=24: send-key(ctrl-alt-delete) — triggers i8042 pulse-output-port reset
        ("seed-sendkey-cad.bin",    &[0x18, 0x0a, 0x00, 0x00]),
        // op=24: send-key(f12) — PXE / BIOS boot menu key
        ("seed-sendkey-f12.bin",    &[0x18, 0x09, 0x00, 0x00]),
        // op=25: mouse_move(20, 10) — exercises PS/2 AUX and USB tablet paths
        ("seed-mouse-move.bin",     &[0x19, 0x14, 0x0a, 0x00]),
        // op=25: mouse_button(1) — left-click press
        ("seed-mouse-button.bin",   &[0x19, 0x01, 0x00, 0x01]),
        // op=26: screendump → /dev/null — exercises VGA framebuffer readout
        ("seed-screendump.bin",     &[0x1a, 0x00, 0x00, 0x00]),
        // op=27: query-pci — walks PCI bus hierarchy
        ("seed-query-pci.bin",      &[0x1b, 0x00, 0x00, 0x00]),
        // op=27: rtc-reset-reinjection — clears RTC lost-tick counter
        ("seed-rtc-reset.bin",      &[0x1b, 0x03, 0x00, 0x00]),
        // Scenario: device_add(usb-tablet) → mouse_move → mouse_button → device_del
        // Tests USB tablet hotplug + HID input delivery path.
        (
            "seed-scenario-usb-mouse.bin",
            &[
                0x02, 0x0b, 0x00, 0x00, // op=2:  device_add(usb-tablet, dev0)
                0x19, 0x20, 0x10, 0x00, // op=25: mouse_move(16, 8)
                0x19, 0x01, 0x00, 0x01, // op=25: mouse_button(1)
                0x18, 0x00, 0x00, 0x00, // op=24: send-key(ret)
                0x03, 0x00, 0x00, 0x00, // op=3:  device_del(dev0)
            ],
        ),
    ];
    for (name, data) in seeds {
        fs::write(path.join(name), data)?;
    }
    Ok(())
}

fn worker_paths(cfg: &Config, worker_id: usize) -> WorkerPaths {
    let worker_label = format!("worker-{worker_id:03}");
    let queue_root = cfg.sync_dir.join("queue");
    let worker_queue_dir = queue_root.join(worker_label.clone());

    let objective_root = cfg.crashes_dir.clone();
    let worker_objective_base_dir = if cfg.worker_id.is_some() || cfg.jobs > 1 {
        objective_root.join(worker_label)
    } else {
        objective_root.clone()
    };
    let worker_objective_all_dir = worker_objective_base_dir.join("all");
    let worker_crash_only_dir = worker_objective_base_dir.join("crashes");
    let worker_timeout_dir = worker_objective_base_dir.join("timeouts");
    let worker_unknown_dir = worker_objective_base_dir.join("unknown");

    WorkerPaths {
        queue_root,
        worker_queue_dir,
        objective_root,
        worker_objective_base_dir,
        worker_objective_all_dir,
        worker_crash_only_dir,
        worker_timeout_dir,
        worker_unknown_dir,
    }
}

fn collect_input_files_recursive(path: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let p = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let md = entry.metadata()?;
        if md.is_dir() {
            collect_input_files_recursive(&p, out)?;
        } else if md.is_file() && md.len() > 0 {
            out.push(p);
        }
    }
    Ok(())
}

fn collect_input_files(roots: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for root in roots {
        collect_input_files_recursive(root, &mut files)?;
    }
    files.sort();
    files.dedup();
    Ok(files)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayVerdict {
    Ok,
    Crash,
    Timeout,
}

fn replay_one_input(cfg: &Config, input: &BytesInput) -> io::Result<ReplayVerdict> {
    let payload = qmp_program_from_bytes(input.target_bytes().as_slice(), cfg.max_commands, false);
    let mut cmd = build_base_qemu_command(&cfg.qemu_bin, &cfg.machine, cfg.debug_qemu);
    cmd.stdout(Stdio::null());

    let mut child = cmd.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("failed to capture replay stdin"))?;
    if let Err(err) = stdin.write_all(&payload) {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return Err(err);
        }
    }
    if let Err(err) = stdin.flush() {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return Err(err);
        }
    }
    drop(stdin);

    let deadline = Instant::now() + Duration::from_millis(cfg.timeout_ms);
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(ReplayVerdict::Ok)
            } else {
                Ok(ReplayVerdict::Crash)
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(ReplayVerdict::Timeout);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn validate_objective_corpus(cfg: &Config, validate_dir: &Path) -> Result<(), Error> {
    if !cfg.qemu_bin.exists() {
        return Err(Error::illegal_argument(format!(
            "QEMU binary does not exist: {}",
            cfg.qemu_bin.display()
        )));
    }
    if !validate_dir.exists() {
        return Err(Error::illegal_argument(format!(
            "validation input dir does not exist: {}",
            validate_dir.display()
        )));
    }

    let files = collect_input_files(&[validate_dir.to_path_buf()])?;
    if files.is_empty() {
        println!(
            "No candidate files found under {}; nothing to validate.",
            validate_dir.display()
        );
        return Ok(());
    }

    let validated_root = cfg
        .validated_dir
        .clone()
        .unwrap_or_else(|| validate_dir.join("validated"));
    let crash_out = validated_root.join("repro-crash");
    let timeout_out = validated_root.join("repro-timeout");
    let invalid_out = validated_root.join("not-repro");
    fs::create_dir_all(&crash_out)?;
    fs::create_dir_all(&timeout_out)?;
    fs::create_dir_all(&invalid_out)?;

    let mut repro_crash = 0usize;
    let mut repro_timeout = 0usize;
    let mut not_repro = 0usize;
    for (idx, path) in files.iter().enumerate() {
        let data = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("failed to read {}: {err}", path.display());
                not_repro += 1;
                continue;
            }
        };
        if data.is_empty() {
            not_repro += 1;
            continue;
        }

        let input = BytesInput::new(data);
        let verdict = replay_one_input(cfg, &input)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("candidate.bin");
        let dest_name = format!("{idx:06}-{name}");

        match verdict {
            ReplayVerdict::Crash => {
                fs::copy(path, crash_out.join(dest_name))?;
                repro_crash += 1;
            }
            ReplayVerdict::Timeout => {
                fs::copy(path, timeout_out.join(dest_name))?;
                repro_timeout += 1;
            }
            ReplayVerdict::Ok => {
                fs::copy(path, invalid_out.join(dest_name))?;
                not_repro += 1;
            }
        }
    }

    println!("Validated {} candidate inputs", files.len());
    println!("  reproducible crashes : {repro_crash}");
    println!("  reproducible timeouts: {repro_timeout}");
    println!("  not reproducible     : {not_repro}");
    println!("  validated output dir : {}", validated_root.display());
    Ok(())
}

fn count_inputs_in_dir(path: &Path) -> io::Result<usize> {
    collect_input_files(&[path.to_path_buf()]).map(|v| v.len())
}

fn classify_objective_files(
    cfg: &Config,
    paths: &WorkerPaths,
) -> Result<(usize, usize, usize), Error> {
    let files = collect_input_files(&[paths.worker_objective_all_dir.clone()])?;
    let mut crash_count = 0usize;
    let mut timeout_count = 0usize;
    let mut unknown_count = 0usize;

    for path in files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let crash_dest = paths.worker_crash_only_dir.join(name);
        let timeout_dest = paths.worker_timeout_dir.join(name);
        let unknown_dest = paths.worker_unknown_dir.join(name);
        if crash_dest.exists() || timeout_dest.exists() || unknown_dest.exists() {
            continue;
        }

        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(_) => {
                fs::copy(&path, &unknown_dest)?;
                unknown_count += 1;
                continue;
            }
        };
        if data.is_empty() {
            fs::copy(&path, &unknown_dest)?;
            unknown_count += 1;
            continue;
        }

        let input = BytesInput::new(data);
        match replay_one_input(cfg, &input)? {
            ReplayVerdict::Crash => {
                fs::copy(&path, &crash_dest)?;
                crash_count += 1;
            }
            ReplayVerdict::Timeout => {
                fs::copy(&path, &timeout_dest)?;
                timeout_count += 1;
            }
            ReplayVerdict::Ok => {
                fs::copy(&path, &unknown_dest)?;
                unknown_count += 1;
            }
        }
    }
    Ok((crash_count, timeout_count, unknown_count))
}

fn parse_next<T: std::str::FromStr>(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<T, String> {
    let value = args
        .next()
        .ok_or_else(|| format!("missing value for {flag}"))?;
    value
        .parse::<T>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn print_help() {
    println!("QEMU QMP device fuzzer (LibAFL)");
    println!();
    println!("Usage:");
    println!("  cargo run -p fuzzer -- [options]");
    println!();
    println!("Options:");
    println!("  --qemu-bin PATH       QEMU binary path (default: {DEFAULT_QEMU_BIN})");
    println!("  --machine NAME        QEMU machine type (default: {DEFAULT_MACHINE})");
    println!("  --seed-dir PATH       Initial seed corpus dir (default: {DEFAULT_SEED_DIR})");
    println!("  --crashes-dir PATH    Objective root dir (default: {DEFAULT_CRASH_DIR})");
    println!("  --sync-dir PATH       Queue sync root dir (default: {DEFAULT_SYNC_DIR})");
    println!("  --iterations N        Fuzz loop iterations per worker (default: {DEFAULT_ITERS})");
    println!(
        "  --timeout-ms N        Timeout per target exec in ms (default: {DEFAULT_TIMEOUT_MS})"
    );
    println!(
        "  --max-commands N      Max generated QMP commands per input (default: {DEFAULT_MAX_COMMANDS})"
    );
    println!("  --jobs N              Number of parallel workers to launch (default: 1)");
    println!(
        "  --sync-interval N     Queue sync stage period in fuzz iterations (default: {DEFAULT_SYNC_INTERVAL})"
    );
    println!(
        "  --session-length N    Testcases per persistent QEMU session, 0=disable (default: {DEFAULT_SESSION_LENGTH})"
    );
    println!("  --validate-dir PATH   Validate corpus files under PATH (replay mode)");
    println!("  --validated-dir PATH  Output dir for validated results (replay mode)");
    println!("  --debug-qemu          Keep QEMU stderr visible");
    println!("  -h, --help            Show this help");
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--qemu-bin" => cfg.qemu_bin = PathBuf::from(parse_next::<String>(&mut args, &arg)?),
            "--machine" => cfg.machine = parse_next::<String>(&mut args, &arg)?,
            "--seed-dir" => cfg.seed_dir = PathBuf::from(parse_next::<String>(&mut args, &arg)?),
            "--crashes-dir" => {
                cfg.crashes_dir = PathBuf::from(parse_next::<String>(&mut args, &arg)?)
            }
            "--sync-dir" => cfg.sync_dir = PathBuf::from(parse_next::<String>(&mut args, &arg)?),
            "--iterations" => cfg.iterations = parse_next::<u64>(&mut args, &arg)?,
            "--timeout-ms" => cfg.timeout_ms = parse_next::<u64>(&mut args, &arg)?,
            "--max-commands" => cfg.max_commands = parse_next::<usize>(&mut args, &arg)?,
            "--jobs" => cfg.jobs = parse_next::<usize>(&mut args, &arg)?,
            "--worker-id" => cfg.worker_id = Some(parse_next::<usize>(&mut args, &arg)?),
            "--sync-interval" => cfg.sync_interval = parse_next::<u64>(&mut args, &arg)?,
            "--session-length" => cfg.session_length = parse_next::<usize>(&mut args, &arg)?,
            "--validate-dir" => {
                cfg.validate_dir = Some(PathBuf::from(parse_next::<String>(&mut args, &arg)?))
            }
            "--validated-dir" => {
                cfg.validated_dir = Some(PathBuf::from(parse_next::<String>(&mut args, &arg)?))
            }
            "--debug-qemu" => cfg.debug_qemu = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if cfg.iterations == 0 {
        return Err("--iterations must be >= 1".to_string());
    }
    if cfg.timeout_ms == 0 {
        return Err("--timeout-ms must be >= 1".to_string());
    }
    if cfg.max_commands == 0 {
        return Err("--max-commands must be >= 1".to_string());
    }
    if cfg.jobs == 0 {
        return Err("--jobs must be >= 1".to_string());
    }
    if cfg.sync_interval == 0 {
        return Err("--sync-interval must be >= 1".to_string());
    }
    if cfg.worker_id.is_some() && cfg.jobs != 1 {
        return Err("--worker-id requires --jobs 1".to_string());
    }
    if cfg.validate_dir.is_some() && (cfg.jobs != 1 || cfg.worker_id.is_some()) {
        return Err("--validate-dir cannot be combined with --jobs > 1 or --worker-id".to_string());
    }
    Ok(cfg)
}

fn run_worker(cfg: &Config, worker_id: usize) -> Result<(), Error> {
    if !cfg.qemu_bin.exists() {
        return Err(Error::illegal_argument(format!(
            "QEMU binary does not exist: {}",
            cfg.qemu_bin.display()
        )));
    }

    ensure_seed_corpus(&cfg.seed_dir)?;

    let paths = worker_paths(cfg, worker_id);
    fs::create_dir_all(&paths.queue_root)?;
    fs::create_dir_all(&paths.worker_queue_dir)?;
    fs::create_dir_all(&paths.objective_root)?;
    fs::create_dir_all(&paths.worker_objective_base_dir)?;
    fs::create_dir_all(&paths.worker_objective_all_dir)?;
    fs::create_dir_all(&paths.worker_crash_only_dir)?;
    fs::create_dir_all(&paths.worker_timeout_dir)?;
    fs::create_dir_all(&paths.worker_unknown_dir)?;

    let input_corpus = InMemoryOnDiskCorpus::<BytesInput>::no_meta(paths.worker_queue_dir.clone())?;
    let objective_corpus = OnDiskCorpus::new(paths.worker_objective_all_dir.clone())?;

    let time_observer = TimeObserver::new("time");
    let stdout_hash_observer = StdOutHashObserver::new("stdout_hash");

    // Corpus entry: only when QEMU response pattern is structurally new.
    // TimeFeedback is intentionally excluded: on a loaded machine QEMU execution
    // time varies enough to produce a "new timing bucket" on nearly every run,
    // causing exponential corpus growth (9M+ files observed in 26 h).
    let mut feedback = NewHashFeedback::new(&stdout_hash_observer);

    // Objective entry: crash AND response pattern not yet seen.
    // The separate NewHashFeedback has its own hash-set so it tracks "novel
    // crashes" independently from the corpus novelty set.  This prevents the
    // same crashing input from being written to disk 1246× (observed previously).
    let obj_hash_dedup = NewHashFeedback::new(&stdout_hash_observer);
    let mut objective = feedback_and!(CrashFeedback::new(), obj_hash_dedup);

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        input_corpus,
        objective_corpus,
        &mut feedback,
        &mut objective,
    )?;

    let monitor_prefix = format!("[worker {worker_id:03}] ");
    let monitor = SimpleMonitor::new(move |s| println!("{monitor_prefix}{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = PersistentQmpExecutor::new(
        cfg.qemu_bin.clone(),
        cfg.machine.clone(),
        Duration::from_millis(cfg.timeout_ms),
        cfg.max_commands,
        if cfg.session_length > 0 { cfg.session_length } else { usize::MAX },
        cfg.debug_qemu,
        tuple_list!(time_observer, stdout_hash_observer),
    );

    if state.corpus().count() < 1 {
        let initial_roots = vec![cfg.seed_dir.clone(), paths.queue_root.clone()];
        let initial_files = collect_input_files(&initial_roots)?;
        if !initial_files.is_empty() {
            state.load_initial_inputs_by_filenames_forced(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                &initial_files,
            )?;
        }
        println!(
            "[worker {worker_id:03}] imported {} initial inputs from {} files",
            state.corpus().count(),
            initial_files.len()
        );
    }

    let havoc_mutator = StdScheduledMutator::new(havoc_mutations());
    let chunk_mutator = StdScheduledMutator::new(tuple_list!(
        ChunkArgMutator::default(),
        ChunkOpMutator::default(),
        ChunkTrimMutator::new(cfg.max_commands),
    ));
    let queue_sync_stage = SyncFromDiskStage::with_from_file(paths.queue_root.clone());
    let sync_interval = cfg.sync_interval;
    let mut sync_tick: u64 = 0;
    let periodic_queue_sync = IfStage::new(
        move |_fuzzer, _executor, _state, _manager, _corpus_idx| {
            sync_tick += 1;
            Ok(sync_tick == 1 || sync_tick % sync_interval == 0)
        },
        tuple_list!(queue_sync_stage),
    );
    // Two mutation passes per fuzz iteration:
    //   1. chunk-aware mutations (preserve structure, improve signal quality)
    //   2. havoc mutations (broad byte-level exploration)
    let mut stages = tuple_list!(
        periodic_queue_sync,
        StdMutationalStage::with_max_iterations(chunk_mutator, 2),
        StdMutationalStage::with_max_iterations(havoc_mutator, 4)
    );

    let (new_crashes_pre, new_timeouts_pre, new_unknowns_pre) =
        classify_objective_files(cfg, &paths)?;
    if new_crashes_pre + new_timeouts_pre + new_unknowns_pre > 0 {
        println!(
            "[worker {worker_id:03}] classified existing objectives: +{} crashes, +{} timeouts, +{} unknown",
            new_crashes_pre, new_timeouts_pre, new_unknowns_pre
        );
    }

    println!(
        "[worker {worker_id:03}] start fuzzing: qemu={}, machine={}, iters={}, timeout={}ms, queue_dir={}, objective_all_dir={}, crash_dir={}, timeout_dir={}, sync_every={}",
        cfg.qemu_bin.display(),
        cfg.machine,
        cfg.iterations,
        cfg.timeout_ms,
        paths.worker_queue_dir.display(),
        paths.worker_objective_all_dir.display(),
        paths.worker_crash_only_dir.display(),
        paths.worker_timeout_dir.display(),
        cfg.sync_interval
    );

    fuzzer.fuzz_loop_for(
        &mut stages,
        &mut executor,
        &mut state,
        &mut mgr,
        cfg.iterations,
    )?;

    let (new_crashes, new_timeouts, new_unknowns) = classify_objective_files(cfg, &paths)?;
    if new_crashes + new_timeouts + new_unknowns > 0 {
        println!(
            "[worker {worker_id:03}] classified objectives: +{} crashes, +{} timeouts, +{} unknown",
            new_crashes, new_timeouts, new_unknowns
        );
    }

    let crash_only_count = count_inputs_in_dir(&paths.worker_crash_only_dir)?;
    let timeout_count = count_inputs_in_dir(&paths.worker_timeout_dir)?;
    let unknown_count = count_inputs_in_dir(&paths.worker_unknown_dir)?;

    println!("[worker {worker_id:03}] finished");
    println!("[worker {worker_id:03}] executions: {}", state.executions());
    println!(
        "[worker {worker_id:03}] corpus entries: {}",
        state.corpus().count()
    );
    println!(
        "[worker {worker_id:03}] objective entries (all): {}",
        state.solutions().count()
    );
    println!(
        "[worker {worker_id:03}] crash objectives: {}",
        crash_only_count
    );
    println!(
        "[worker {worker_id:03}] timeout objectives: {}",
        timeout_count
    );
    println!(
        "[worker {worker_id:03}] unknown objectives: {}",
        unknown_count
    );
    println!(
        "[worker {worker_id:03}] shared queue root: {}",
        paths.queue_root.display()
    );
    println!(
        "[worker {worker_id:03}] objective root: {}",
        paths.objective_root.display()
    );
    Ok(())
}

fn launch_parallel_workers(cfg: &Config) -> Result<(), Error> {
    let exe = env::current_exe()?;
    println!("Launching {} workers using {}", cfg.jobs, exe.display());

    let mut children: Vec<(usize, Child)> = Vec::with_capacity(cfg.jobs);
    for worker_id in 0..cfg.jobs {
        let mut cmd = Command::new(&exe);
        cmd.arg("--qemu-bin")
            .arg(&cfg.qemu_bin)
            .arg("--machine")
            .arg(&cfg.machine)
            .arg("--seed-dir")
            .arg(&cfg.seed_dir)
            .arg("--crashes-dir")
            .arg(&cfg.crashes_dir)
            .arg("--sync-dir")
            .arg(&cfg.sync_dir)
            .arg("--iterations")
            .arg(cfg.iterations.to_string())
            .arg("--timeout-ms")
            .arg(cfg.timeout_ms.to_string())
            .arg("--max-commands")
            .arg(cfg.max_commands.to_string())
            .arg("--sync-interval")
            .arg(cfg.sync_interval.to_string())
            .arg("--session-length")
            .arg(cfg.session_length.to_string())
            .arg("--jobs")
            .arg("1")
            .arg("--worker-id")
            .arg(worker_id.to_string());
        if cfg.debug_qemu {
            cmd.arg("--debug-qemu");
        }

        let child = cmd.spawn()?;
        children.push((worker_id, child));
    }

    let mut failed = false;
    for (worker_id, mut child) in children {
        let status = child.wait()?;
        if !status.success() {
            failed = true;
            eprintln!("worker {worker_id:03} exited with status {status}");
        }
    }

    if failed {
        return Err(Error::unknown("one or more workers failed"));
    }
    println!("All workers finished successfully.");
    Ok(())
}

fn main() -> Result<(), Error> {
    let cfg = parse_args().map_err(Error::illegal_argument)?;

    if let Some(validate_dir) = cfg.validate_dir.clone() {
        return validate_objective_corpus(&cfg, &validate_dir);
    }

    if cfg.jobs > 1 && cfg.worker_id.is_none() {
        return launch_parallel_workers(&cfg);
    }

    let worker_id = cfg.worker_id.unwrap_or(0);
    run_worker(&cfg, worker_id)
}
