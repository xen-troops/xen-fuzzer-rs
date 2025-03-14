//! A fuzzer using qemu in systemmode for binary-only coverage of Xen hypervisor

use core::{ptr::addr_of_mut, time::Duration};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, fs, path::PathBuf, process, time::Instant};

use libafl_bolts::os::CTRL_C_EXIT;

use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{EventRestarter, SimpleRestartingEventManager},
    executors::ShadowExecutor,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{
        I2SRandReplaceBinonly,
        {havoc_mutations, scheduled::StdScheduledMutator},
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, HasSolutions, StdState},
    Error,
};
use libafl_bolts::{
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    emu::Emulator,
    executor::QemuExecutor,
    modules::{cmplog::CmpLogObserver, edges::StdEdgeCoverageModule, CmpLogModule},
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use std::io::{self, Write};

use crate::Cli;
use crate::Commands;

fn create_args(cli: &Cli) -> Vec<String> {
    let mut l_xen_path = "target/xen/xen/xen";
    let l_fuzzer_path: String;
    match &cli.command {
        Some(Commands::Raw(args)) => {
            return args.to_vec();
        }
        Some(Commands::Run {
            xen_path,
            fuzzer_path,
        }) => {
            l_xen_path = xen_path;
            l_fuzzer_path = fuzzer_path.to_string()
        }
        Some(Commands::Vgic {}) => {
            l_fuzzer_path =
                "target/xtf/tests/arm-vgic-fuzzer/test-mmu64le-arm-vgic-fuzzer".to_string()
        }
        Some(Commands::Hypercalls {}) => {
            l_fuzzer_path =
                "target/xtf/tests/arm-hypercall-fuzzer/test-mmu64le-arm-hypercall-fuzzer"
                    .to_string()
        }
        None => {
            panic!("How we even got here?")
        }
    }

    let mut args: Vec<String> = vec![
        "", // placeholder for executable name
        "-accel",
        "tcg",
        "-machine",
        "virt,virtualization=yes,acpi=off,gic-version=2",
        "-L",
        "target/debug/qemu-libafl-bridge/pc-bios",
        "-m",
        "4G",
        "-nographic",
        "-cpu",
        "max",
        "-append",
        "dom0_mem=512M loglvl=all guest_loglvl=none console=dtuart",
        "-snapshot",
        "-kernel",
        l_xen_path,
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect();

    args[0] = env::args().nth(0).unwrap();

    args.push("-device".to_string());
    args.push(format!(
        "guest-loader,addr=0x42000000,kernel={l_fuzzer_path},bootargs=''"
    ));

    args
}

pub fn replay(cli: &Cli) -> process::ExitCode {
    let input_data = fs::read(cli.replay.as_ref().unwrap()).expect("Can't read crash data");

    let qemu_args = create_args(&cli);
    println!("QEMU args = {:?}", qemu_args);

    let mut emulator = Emulator::builder()
        .qemu_parameters(qemu_args)
        .modules(())
        .build()
        .expect("Can't create emulator instance");

    let devices = emulator.list_devices();
    println!("Devices = {:?}", devices);

    let mut state = StdState::nop().unwrap();
    let input = BytesInput::from(input_data);
    unsafe {
        let _ = emulator.run(&mut state, &input);
    }
    process::ExitCode::SUCCESS
}

pub fn fuzz(cli: &Cli) -> process::ExitCode {
    let running_time = Instant::now();

    // Hardcoded parameters
    let timeout = Duration::from_secs(60);
    let corpus_dirs = [PathBuf::from("./corpus")];
    let objective_dir = PathBuf::from("./crashes");

    let mut shmem_provider = StdShMemProvider::new().unwrap();

    let mut objective_cnt_shmem = shmem_provider
        .new_on_shmem::<AtomicUsize>(AtomicUsize::new(0))
        .unwrap();

    // Use this atomic to count objective between fuzzer restarts
    let objective_cnt =
        unsafe { AtomicUsize::from_ptr(objective_cnt_shmem.as_mut_ptr().cast::<usize>()) };

    // The stats reporter for the broker
    // We ignore writeln! result, because there actually little we can do in
    // this case. We can get fault here becase QEMU configures stdout
    // in non-blocking mode, which causes issues with default println!
    // implementation.
    let monitor = MultiMonitor::new(|s| {
        let _ = writeln!(io::stdout(), "{s}");
    });

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as
        // child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                if objective_cnt.load(Ordering::Relaxed) > 0 {
                    println!(
                        "Found {} objectives (crashes)",
                        objective_cnt.load(Ordering::Relaxed)
                    );
                    return process::ExitCode::FAILURE;
                } else {
                    println!("No objectives found, all good!");
                    return process::ExitCode::SUCCESS;
                }
            }
            _ => {
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };

    let qemu_args = create_args(&cli);
    println!("QEMU args = {:?}", qemu_args);

    // Create an observation channel using the coverage map
    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
            addr_of_mut!(MAX_EDGES_FOUND),
        ))
        .track_indices()
    };

    // Choose modules to use
    let modules = tuple_list!(
        StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()
            .expect("Failed to build StdEdgeCoverageModule"),
        CmpLogModule::default(),
    );

    let emu = Emulator::builder()
        .qemu_parameters(qemu_args)
        .modules(modules)
        .build()
        .expect("Failed to build Emulator");

    let devices = emu.list_devices();
    println!("Devices = {:?}", devices);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness =
        |emulator: &mut Emulator<_, _, _, _, _, _, _>, state: &mut _, input: &BytesInput| unsafe {
            emulator.run(state, input).unwrap().try_into().unwrap()
        };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Create a cmplog observer
    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::new("corpus_gen").unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir.clone()).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create a QEMU in-process executor
    let mut executor = QemuExecutor::new(
        emu,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )
    .expect("Failed to create QemuExecutor");

    // Instead of calling the timeout handler and restart the process, trigger a breakpoint ASAP
    executor.break_on_timeout();

    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
        .unwrap_or_else(|_| {
            println!("Failed to load initial corpus at {:?}", &corpus_dirs);
            process::exit(1);
        });
    println!("We imported {} inputs from disk.", state.corpus().count());

    // a CmpLog-based mutational stage
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
        I2SRandReplaceBinonly::new()
    )));

    // Setup an havoc mutator with a mutational stage
    let tracing = ShadowTracingStage::new();
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(tracing, i2s, StdMutationalStage::new(mutator),);

    let test_time = cli.test_time.map(|x| Duration::from_secs(x));
    while test_time.map_or(true, |x| running_time.elapsed() < x) {
        log::debug!("Running time: {}s", running_time.elapsed().as_secs());
        fuzzer
            .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 10)
            .expect("fuzz_loop error");
        mgr.on_restart(&mut state)
            .expect("Failed to update restarter state");
    }

    objective_cnt.fetch_add(state.solutions().count(), Ordering::Relaxed);

    // We mimic behavior from libafl_qemu::mod.rs by calling std::process::exit().
    // mgr.send_exiting() seems like a more sane approach, but it breaks libafl
    // state for some reason.
    println!("Reached execution time limit. Exiting.");

    std::process::exit(CTRL_C_EXIT);
}
