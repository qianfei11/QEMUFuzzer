use std::{
    collections::hash_map::DefaultHasher,
    env, fs,
    hash::{Hash, Hasher},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{command::CommandConfigurator, CommandExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, NewHashFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, Input, UsesInput},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{Observer, ObserverWithHashField, TimeObserver},
    schedulers::QueueScheduler,
    stages::{IfStage, StdMutationalStage, SyncFromDiskStage},
    state::{HasCorpus, HasExecutions, HasSolutions, StdState},
    Error,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice, Named};
use serde::{Deserialize, Serialize};

const DEFAULT_QEMU_BIN: &str = "/usr/bin/qemu-system-x86_64";
const DEFAULT_MACHINE: &str = "q35";
const DEFAULT_SEED_DIR: &str = "corpus";
const DEFAULT_CRASH_DIR: &str = "crashes";
const DEFAULT_SYNC_DIR: &str = "sync";
const DEFAULT_ITERS: u64 = 5000;
const DEFAULT_TIMEOUT_MS: u64 = 1200;
const DEFAULT_MAX_COMMANDS: usize = 16;
const DEFAULT_SYNC_INTERVAL: u64 = 50;

const DEVICE_DRIVERS: &[&str] = &["e1000", "rtl8139", "virtio-rng-pci", "edu", "pc-testdev"];
const QUERY_COMMANDS: &[&str] = &[
    "query-status",
    "query-version",
    "query-machines",
    "query-cpus-fast",
    "query-hotpluggable-cpus",
    "query-memory-devices",
    "query-pci",
    "query-commands",
];
const HMP_COMMANDS: &[&str] = &[
    "help",
    "info pci",
    "info qtree",
    "info mtree",
    "info block",
    "info network",
    "info qom-tree",
    "info irq",
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
        }
    }
}

#[derive(Debug, Clone)]
struct WorkerPaths {
    queue_root: PathBuf,
    worker_queue_dir: PathBuf,
    objective_root: PathBuf,
    worker_objective_dir: PathBuf,
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
        let mut hasher = DefaultHasher::new();
        stdout.hash(&mut hasher);
        self.hash = Some(hasher.finish());
    }
}

#[derive(Debug)]
struct QmpConfigurator {
    qemu_bin: PathBuf,
    machine: String,
    timeout: Duration,
    max_commands: usize,
    debug_child: bool,
}

impl QmpConfigurator {
    fn command_template(&self) -> Command {
        let mut cmd = Command::new(&self.qemu_bin);
        cmd.arg("-machine")
            .arg(&self.machine)
            .arg("-display")
            .arg("none")
            .arg("-monitor")
            .arg("none")
            .arg("-serial")
            .arg("none")
            .arg("-qmp")
            .arg("stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());

        if self.debug_child {
            cmd.stderr(Stdio::inherit());
        } else {
            cmd.stderr(Stdio::null());
        }
        cmd
    }
}

impl CommandConfigurator for QmpConfigurator {
    fn spawn_child<I>(&mut self, input: &I) -> Result<Child, Error>
    where
        I: Input + HasTargetBytes,
    {
        let mut child = self.command_template().spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::illegal_state("failed to capture child stdin"))?;
        let payload = qmp_program_from_bytes(input.target_bytes().as_slice(), self.max_commands);

        if let Err(err) = stdin.write_all(&payload) {
            if err.kind() != io::ErrorKind::BrokenPipe {
                return Err(err.into());
            }
        }
        if let Err(err) = stdin.flush() {
            if err.kind() != io::ErrorKind::BrokenPipe {
                return Err(err.into());
            }
        }
        drop(stdin);
        Ok(child)
    }

    fn exec_timeout(&self) -> Duration {
        self.timeout
    }
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

fn qmp_program_from_bytes(data: &[u8], max_commands: usize) -> Vec<u8> {
    let mut cmds = String::with_capacity(1024);
    let mut next_device_id: u64 = 0;
    let mut live_devices: Vec<String> = Vec::new();

    push_exec(&mut cmds, "qmp_capabilities");
    push_exec(&mut cmds, "query-commands");

    for chunk in data.chunks(3).take(max_commands) {
        let op = chunk[0] % 6;
        match op {
            0 => {
                let query = QUERY_COMMANDS
                    [(chunk.get(1).copied().unwrap_or(0) as usize) % QUERY_COMMANDS.len()];
                push_exec(&mut cmds, query);
            }
            1 => {
                let hmp = HMP_COMMANDS
                    [(chunk.get(1).copied().unwrap_or(0) as usize) % HMP_COMMANDS.len()];
                push_hmp(&mut cmds, hmp);
            }
            2 => {
                let driver = DEVICE_DRIVERS
                    [(chunk.get(1).copied().unwrap_or(0) as usize) % DEVICE_DRIVERS.len()];
                let id = format!("dev{next_device_id}");
                next_device_id += 1;
                push_device_add(&mut cmds, driver, &id);
                live_devices.push(id);
            }
            3 => {
                if live_devices.is_empty() {
                    push_exec(&mut cmds, "query-status");
                } else {
                    let pick = (chunk.get(1).copied().unwrap_or(0) as usize) % live_devices.len();
                    let id = live_devices.swap_remove(pick);
                    push_device_del(&mut cmds, &id);
                }
            }
            4 => {
                cmds.push_str("{\"execute\":\"qom-list\",\"arguments\":{\"path\":\"/machine\"}}\n");
            }
            _ => {
                cmds.push_str(
                    "{\"execute\":\"query-command-line-options\",\"arguments\":{\"option\":\"device\"}}\n",
                );
            }
        }
    }

    for id in &live_devices {
        push_device_del(&mut cmds, id);
    }
    push_exec(&mut cmds, "quit");
    cmds.into_bytes()
}

fn ensure_seed_corpus(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    if fs::read_dir(path)?.next().is_some() {
        return Ok(());
    }

    let seeds: [(&str, &[u8]); 6] = [
        ("seed-query.bin", &[0x00, 0x00, 0x00, 0x00]),
        ("seed-hmp.bin", &[0x01, 0x00, 0x00, 0x00]),
        ("seed-device-add.bin", &[0x02, 0x00, 0x00, 0x02, 0x01, 0x00]),
        (
            "seed-device-cycle.bin",
            &[0x02, 0x02, 0x00, 0x03, 0x00, 0x00],
        ),
        ("seed-qom.bin", &[0x04, 0x00, 0x00]),
        ("seed-options.bin", &[0x05, 0x00, 0x00]),
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
    let worker_objective_dir = if cfg.worker_id.is_some() || cfg.jobs > 1 {
        objective_root.join(worker_label)
    } else {
        objective_root.clone()
    };

    WorkerPaths {
        queue_root,
        worker_queue_dir,
        objective_root,
        worker_objective_dir,
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
    fs::create_dir_all(&paths.worker_objective_dir)?;

    let input_corpus = InMemoryOnDiskCorpus::<BytesInput>::no_meta(paths.worker_queue_dir.clone())?;
    let objective_corpus = OnDiskCorpus::new(paths.worker_objective_dir.clone())?;

    let time_observer = TimeObserver::new("time");
    let stdout_hash_observer = StdOutHashObserver::new("stdout_hash");

    let mut feedback = feedback_or!(
        NewHashFeedback::new(&stdout_hash_observer),
        TimeFeedback::with_observer(&time_observer)
    );
    let mut objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

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

    let qmp_executor = QmpConfigurator {
        qemu_bin: cfg.qemu_bin.clone(),
        machine: cfg.machine.clone(),
        timeout: Duration::from_millis(cfg.timeout_ms),
        max_commands: cfg.max_commands,
        debug_child: cfg.debug_qemu,
    };
    let mut executor: CommandExecutor<_, _, _> =
        qmp_executor.into_executor(tuple_list!(time_observer, stdout_hash_observer));

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

    let mutator = StdScheduledMutator::new(havoc_mutations());
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
    let mut stages = tuple_list!(
        periodic_queue_sync,
        StdMutationalStage::with_max_iterations(mutator, 1)
    );

    println!(
        "[worker {worker_id:03}] start fuzzing: qemu={}, machine={}, iters={}, timeout={}ms, queue_dir={}, objective_dir={}, sync_every={}",
        cfg.qemu_bin.display(),
        cfg.machine,
        cfg.iterations,
        cfg.timeout_ms,
        paths.worker_queue_dir.display(),
        paths.worker_objective_dir.display(),
        cfg.sync_interval
    );

    fuzzer.fuzz_loop_for(
        &mut stages,
        &mut executor,
        &mut state,
        &mut mgr,
        cfg.iterations,
    )?;

    println!("[worker {worker_id:03}] finished");
    println!("[worker {worker_id:03}] executions: {}", state.executions());
    println!(
        "[worker {worker_id:03}] corpus entries: {}",
        state.corpus().count()
    );
    println!(
        "[worker {worker_id:03}] objective entries: {}",
        state.solutions().count()
    );
    println!(
        "[worker {worker_id:03}] shared queue root: {}",
        paths.queue_root.display()
    );
    println!(
        "[worker {worker_id:03}] shared objective root: {}",
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

    if cfg.jobs > 1 && cfg.worker_id.is_none() {
        return launch_parallel_workers(&cfg);
    }

    let worker_id = cfg.worker_id.unwrap_or(0);
    run_worker(&cfg, worker_id)
}
