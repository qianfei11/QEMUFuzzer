use std::{
    path::PathBuf, time::Duration
};
use libafl_bolts::{
    tuples::tuple_list,
    shmem::{
        ShMem,
        ShMemProvider,
        StdShMemProvider,
    },
    rands::StdRand,
    current_nanos,
    AsMutSlice,
};
use libafl::{
    corpus::{
        Corpus,
        InMemoryCorpus,
        OnDiskCorpus,
    },
    events::SimpleEventManager,
    executors::{
        ForkserverExecutor,
        TimeoutForkserverExecutor,
    },
    feedbacks::{
        MaxMapFeedback,
        TimeFeedback,
        TimeoutFeedback,
    },
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations,
        StdScheduledMutator,
    },
    observers::{
        HitcountsMapObserver,
        StdMapObserver,
        TimeObserver,
    },
    schedulers::{
        IndexesLenTimeMinimizerScheduler,
        QueueScheduler,
    },
    stages::StdMutationalStage,
    state::{
        HasCorpus,
        StdState,
    },
    Error,
    Fuzzer,
    feedback_and_fast,
    feedback_or,
    StdFuzzer,
};

/// size of the shared memory mapping used as the coverage map
const MAP_SIZE: usize = 65536;

fn main() -> Result<(), Error> {
    println!("Hello, world!");

    // Component: Corpus
    // path to input corpus
    let corpus_dirs = vec![PathBuf::from("./corpus")];

    // keep the corpus in memory for performance
    let input_corpus = InMemoryCorpus::<BytesInput>::new();

    // timeout corpus to store in disk
    let timeout_corpus = OnDiskCorpus::new(PathBuf::from("./timeouts")).expect("Could not create timeouts corpus");

    // Component: Observer
    // use the time of the execution as the observer
    let time_observer = TimeObserver::new("time");

    // create a shared memory for the Observer and the Executor
    let mut shmem_provider = StdShMemProvider::new()?;
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE)?;
    // write the shared memory ID to the environment
    shmem.write_to_env("__AFL_SHM_ID").expect("couldn't write shared memory ID");
    // get a mutable reference to the memory
    let shmem_buf = shmem.as_mut_slice();

    // create the observer using the shared memory
    let edges_observer = unsafe { HitcountsMapObserver::new(StdMapObserver::new("share_mem", shmem_buf)) };

    // Component: Feedback
    // create a feedback that uses the edges_observer or the time_observer
    let mut feedback = feedback_or!(
        MaxMapFeedback::tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer)
    );

    // create a feedback that uses the edges_observer and the time_observer
    let mut objective = feedback_and_fast!(
        TimeoutFeedback::new(),
        MaxMapFeedback::new(&edges_observer)
    );

    // Component: State
    // create a state takes ownership of feedback, a random number generator and corpora
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        input_corpus,
        timeout_corpus,
        &mut feedback,
        &mut objective,
    )?;

    // Component: Monitor
    // create a monitor that prints the input
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

    // Component: EventManager
    // event manager handles the events during the fuzzing loop
    let mut mgr = SimpleEventManager::new(monitor);

    // Component: Scheduler
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    // Component: Fuzzer
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Component: Executor
    let fork_server = ForkserverExecutor::builder()
        .program("./qemu/build/aarch64-softmmu/qemu-system-aarch64")
        .parse_afl_cmdline(["@@"])
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(time_observer, edges_observer))?;

    let timeout = Duration::from_secs(5);

    // Component: Executor
    let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout)?;

    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!("Failed to load initial corpus: {:?}: {:?}", &corpus_dirs, err)
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // Component: Mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());

    // Component: Stage
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in the fuzzing loop");

    Ok(())
}
