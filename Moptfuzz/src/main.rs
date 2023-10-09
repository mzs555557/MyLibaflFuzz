use core:: {
    cell::RefCell,
    time::Duration
};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process
};
use clap::{Arg, ArgAction,Command};

use libafl::{
    Error, 
    feedbacks::{
        MaxMapFeedback,
        CrashFeedback
    },
    schedulers::{
        IndexesLenTimeMinimizerScheduler,
        StdWeightedScheduler,
        QueueScheduler,
        WeightedScheduler, powersched::PowerSchedule
    },
    executors::{
        ForkserverExecutor,
        TimeoutForkserverExecutor,
        InProcessExecutor,
        TimeoutExecutor
    },
    observers::{
        HitcountsIterableMapObserver,
        StdMapObserver,
        TimeObserver,
        HitcountsMapObserver,
    },
    corpus::{
        OnDiskCorpus,
        InMemoryOnDiskCorpus
    },
    inputs::{
        BytesInput
    },
    state::{
        StdState
    },
    events::{
        SimpleEventManager,
    },
    monitors::{
        SimpleMonitor,
        MultiMonitor,
        
    },
    mutators::{
        Tokens,
        scheduled::havoc_mutations,
        token_mutations::AFLppRedQueen,
        tokens_mutations,
        StdMOptMutator
    },
    stages::{
        CalibrationStage, StdPowerMutationalStage, ColorizationStage
    }, feedback_and, prelude::TimeFeedback, StdFuzzer, Fuzzer,feedback_or,feedback_or_fast

};

use libafl_bolts::{
    current_time,
    current_nanos,
    shmem:: {
        ShMem,
        ShMemProvider,
        UnixShMemProvider
    },
    tuples::{tuple_list, Merge},
    AsMutSlice, rands::StdRand
};

use libafl_targets:: {
    libfuzzer_initialize,
    libfuzzer_test_one_input,
    std_edges_map_observer
};

pub fn main() {

    let res = match Command::new(env!("CARGO_PKG_NAME")) 
        .version(env!("CARGO_PKG_NAME"))
        .author("mzs")
        .about("mzs designed fuzzer")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        )
        .arg(
            Arg::new("logfile")
                .short('l')
                .long("log")
                .help("The directory to read initial inputs from ('seeds')")
                .default_value("libafl.log"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("1200"),
        )
        .arg(
            Arg::new("exec")
                .short('e')
                .help("The instrumented binary we want to fuzz")
                .required(true)
        )
        .arg(
            Arg::new("arguments")
            .long("arguments")
            .help("arguments")
            .num_args(1..)
        )
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir -i seed_dir\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(
        res.get_one::<String>("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }

    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(
        res.get_one::<String>("in")
            .expect("The --input parameter is missing")
            .to_string(),
    );
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let executable = res
        .get_one::<String>("exec")
        .expect("The executable is missing")
        .to_string();

    println!("input dir is {:?}, output dir is {:?}, exec program is {:?}",
            in_dir,
            out_dir,
            executable
        );

    let arguments = res
        .get_many::<String>("arguments")
        .map(|v| v.map(std::string::ToString::to_string).collect::<Vec<_>>())
        .unwrap_or_default();

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    let logfile = PathBuf::from(res.get_one::<String>("logfile").unwrap().to_string());
    println!("arguments is {:?}", arguments);
    
    fuzz(
        out_dir,
        crashes,
        &in_dir,
        &logfile,
        timeout,
        executable,
        &arguments
    )
    .expect("An error occurred while fuzzing")

}

fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir:&PathBuf,
    logfile: &PathBuf,
    timeout: Duration,
    executable: String,
    arguments: &[String]
) -> Result<(),Error>{
    const  MAP_SIZE:usize = 2_621_440;

    let log: RefCell<fs::File> = RefCell::new(OpenOptions::new().append(true).create(true).open(logfile)?);

    let monitor = MultiMonitor::new(|s| {
        println!("{s}");
        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    });
    
    // println!("{:?}", monitor);
    // println!("corpus is {:?}.", seed_dir);


    let mut mgr = 
            SimpleEventManager::new(monitor);
    
    let mut shmem_provider = 
            UnixShMemProvider::new().unwrap();

    let mut shmem = 
            shmem_provider.new_shmem(MAP_SIZE).unwrap();

    shmem.write_to_env("__AFL_SHM_ID").unwrap();

    let shmem_buf = shmem.as_mut_slice();

    // To let know the AFL++ binary that we have a big map
    std::env::set_var("AFL_MAP_SIZE", format!("{MAP_SIZE}"));

    let edges_observer = 
    unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)) };

    let edges_observer_edge = HitcountsMapObserver::new(
        unsafe { std_edges_map_observer("edges") }
    );

    println!("edges observer: {:?}.", edges_observer_edge);

    let time_obeserver = TimeObserver::new("time");

    let map_feedback = MaxMapFeedback::tracking(
        &edges_observer, 
        true, 
        false
    );

    let calibration = 
        CalibrationStage::new(
            &map_feedback
        );
    
    // let calibration = CalibrationStage::new(&map_feedback);

    let mut feedback = 
    feedback_or!(
        map_feedback,
        TimeFeedback::with_observer(&time_obeserver)
    );

    let mut objective = CrashFeedback::new();

    let mut state = 
        StdState::new(
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::<BytesInput>::new(corpus_dir).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
    )
    .unwrap();

    // println!("state is {:?}.", state);    
    println!("Let's fuzz :)");

    let mutator = 
        StdMOptMutator::new(
            &mut state, 
            havoc_mutations().merge(tokens_mutations()), 
            8, 
            5
    )?;

    let power = 
        StdPowerMutationalStage::new(mutator);

    
    let sheduler = 
    IndexesLenTimeMinimizerScheduler::new(
        StdWeightedScheduler::with_schedule(
            &mut state, 
            &edges_observer, 
            Some(PowerSchedule::EXPLORE))    
    );

    let mut fuzzer = 
        StdFuzzer::new(
            sheduler,
            feedback,
            objective
        );

    // let colorization = 
    //     ColorizationStage::new(&edges_observer);

    let mut tokens = Tokens::new();
    
    println!(" token is {:?}", tokens);
    let forkserver = ForkserverExecutor::builder()
        .program(executable)
        .shmem_provider(&mut shmem_provider)
        .autotokens(& mut tokens)
        .parse_afl_cmdline(arguments)
        .coverage_map_size(MAP_SIZE)
        .is_persistent(true)
        .build_dynamic_map(edges_observer, tuple_list!(time_obeserver,edges_observer_edge))
        .unwrap();

    let mut executor = 
        TimeoutForkserverExecutor::new(forkserver, timeout)
        .expect("Failed to create the executor.");

    state.load_initial_inputs(
        &mut fuzzer,
        &mut executor, 
        &mut mgr, 
        &[seed_dir.clone()]
    )
    .unwrap_or_else(|_| {
        println!("Failed to load initial corpus at {:?}", &seed_dir);
        process::exit(0);
    });

    // println!("mopt mutator is {:?}", mutator);
    let mut stages = tuple_list!(calibration, power);

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}