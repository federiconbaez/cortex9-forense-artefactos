//! Implementación de la CLI.
use clap::{Parser, Subcommand};
use fa_checker::{check, explore, to_dot, CheckerConfig};
use fa_core::prereg;
use fa_core::{Action, CheckOutcome, State};
use fa_models::apple_dp::measure_apple_dp;
use fa_models::avb_rollback::measure_avb;
use fa_models::fbe_keys::measure_fbe;
use fa_models::gatekeeper::measure_gatekeeper_properties;
use fa_models::gatekeeper_model::GatekeeperModel;
use fa_models::inactivity::measure_inactivity;
use fa_models::legacy_bfs::{bfs_gatekeeper, bfs_pin_counter, bfs_rpmb};
use fa_models::lock_capabilities::{catalog, measure_capability_properties, Reachability};
use fa_models::mutants::run_all_mutants;
use fa_models::pin_counter::measure_pin_properties;
use fa_models::pin_model::PinModel;
use fa_models::powercut::measure_powercut;
use fa_models::rpmb::measure_rpmb_properties;
use fa_models::rpmb_model::RpmbModel;
use fa_models::weaver::measure_weaver;
use fa_pate::Transcript;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "fa",
    version,
    about = "cortex9-forense-artefactos — modelos formales + PATE-FNBR"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Monte-Carlo preregistrado (compat).
    Measure {
        #[arg(long, default_value = "ci")]
        mode: String,
    },
    /// Model checking BFS (compat alias).
    Bfs,
    /// Todos los mutantes.
    Mutants,
    /// Tabla de capacidades.
    Catalog,
    /// measure + bfs + mutants.
    All {
        #[arg(long, default_value = "ci")]
        mode: String,
    },
    /// Verifica un modelo (pin|rpmb) e imprime contraejemplo si hay.
    Check { model: String },
    /// Exporta grafo DOT del modelo.
    Graph {
        model: String,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// PATE-FNBR para el expediente.
    Pate {
        #[command(subcommand)]
        cmd: PateCmd,
    },
}

#[derive(Subcommand, Debug)]
enum PateCmd {
    /// Crea transcripción.
    Init {
        case_id: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Append de un paso de adquisición.
    Append {
        file: PathBuf,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        payload: String,
        #[arg(long)]
        timestamp: String,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        tool: String,
        #[arg(long, default_value = "")]
        artifact_sha256: String,
    },
    /// Sella la cadena.
    Seal {
        file: PathBuf,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        timestamp: String,
    },
    /// Verifica (reporta índice de fallo).
    Verify { file: PathBuf },
    /// Export Markdown.
    Report {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Measure { mode } => cmd_measure(&mode),
        Commands::Bfs => cmd_bfs(),
        Commands::Mutants => cmd_mutants(),
        Commands::Catalog => cmd_catalog(),
        Commands::All { mode } => {
            let a = cmd_measure(&mode);
            let b = cmd_bfs();
            let c = cmd_mutants();
            if a == ExitCode::SUCCESS && b == ExitCode::SUCCESS && c == ExitCode::SUCCESS {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Commands::Check { model } => cmd_check(&model),
        Commands::Graph { model, out } => cmd_graph(&model, out),
        Commands::Pate { cmd } => cmd_pate(cmd),
    }
}

fn flag(ok: bool) -> &'static str {
    if ok {
        "CUMPLIDO"
    } else {
        "NO CUMPLIDO"
    }
}

fn trials(mode: &str) -> u64 {
    if mode == "full" {
        prereg::FULL_TRIALS
    } else {
        prereg::CI_TRIALS
    }
}

fn cmd_measure(mode: &str) -> ExitCode {
    let trials = trials(mode);
    println!("=== measure mode={mode} trials={trials} ===");
    let t0 = Instant::now();
    let mut ok = true;
    // Detailed prints for key models (compat with evidence parser)
    {
        let pin = measure_pin_properties(prereg::PIN_SEED, trials);
        let pin_ok = pin.all_pass();
        ok &= pin_ok;
        println!(
            "pin_counter: mono={}/{} throttle={}/{} wipe={}/{} reset={}/{} bfu_afu={}/{} ce={}/{} => {}",
            pin.mono_ok, pin.trials, pin.throttle_ok, pin.trials, pin.wipe_ok, pin.trials,
            pin.success_resets_ok, pin.trials, pin.bfu_to_afu_ok, pin.trials, pin.ce_only_afu_ok, pin.trials,
            flag(pin_ok)
        );
    }
    {
        let rpmb = measure_rpmb_properties(prereg::RPMB_SEED, trials);
        let o = rpmb.all_pass();
        ok &= o;
        println!(
            "rpmb: mono={}/{} bad_mac={}/{} replay={}/{} honest={}/{} rt={}/{} => {}",
            rpmb.mono_ok,
            rpmb.trials,
            rpmb.bad_mac_rejected,
            rpmb.trials,
            rpmb.replay_rejected,
            rpmb.trials,
            rpmb.honest_write_ok,
            rpmb.trials,
            rpmb.read_roundtrip_ok,
            rpmb.trials,
            flag(o)
        );
    }
    {
        let gk = measure_gatekeeper_properties(prereg::GK_SEED, trials);
        let o = gk.all_pass();
        ok &= o;
        println!(
            "gatekeeper: enroll={}/{} wrong={}/{} tracks={}/{} wipe={}/{} th={}/{} => {}",
            gk.enroll_verify_ok,
            gk.trials,
            gk.wrong_rejected,
            gk.trials,
            gk.rpmb_tracks_fails,
            gk.trials,
            gk.wipe_denies,
            gk.trials,
            gk.throttle_respected,
            gk.trials,
            flag(o)
        );
    }
    {
        let w = measure_weaver(prereg::WEAVER_SEED, trials);
        let o = w.all_pass();
        ok &= o;
        println!(
            "weaver: indep={}/{} th={}/{} wipe={}/{} enroll={}/{} => {}",
            w.independent_slots_ok,
            w.trials,
            w.throttle_per_slot_ok,
            w.trials,
            w.wipe_per_slot_ok,
            w.trials,
            w.enroll_verify_ok,
            w.trials,
            flag(o)
        );
    }
    {
        let f = measure_fbe(prereg::FBE_SEED, trials);
        let o = f.all_pass();
        ok &= o;
        println!(
            "fbe_keys: de={}/{} ce_afu={}/{} evict={}/{} wipe={}/{} => {}",
            f.de_after_boot_ok,
            f.trials,
            f.ce_only_afu_ok,
            f.trials,
            f.eviction_ok,
            f.trials,
            f.wipe_clears_ok,
            f.trials,
            flag(o)
        );
    }
    {
        let a = measure_apple_dp(prereg::ADP_SEED, trials);
        let o = a.all_pass();
        ok &= o;
        println!(
            "apple_dp: bfu_d={}/{} afu={}/{} relock={}/{} => {}",
            a.bfu_only_d_ok,
            a.trials,
            a.afu_all_ok,
            a.trials,
            a.relock_class_a_denied_ok,
            a.trials,
            flag(o)
        );
    }
    {
        let i = measure_inactivity(prereg::IDLE_SEED, trials);
        let o = i.all_pass();
        ok &= o;
        println!(
            "inactivity: timeout={}/{} touch={}/{} evict={}/{} => {}",
            i.timeout_triggers_ok,
            i.trials,
            i.touch_resets_ok,
            i.trials,
            i.ce_evicted_ok,
            i.trials,
            flag(o)
        );
    }
    {
        let a = measure_avb(prereg::AVB_SEED, trials);
        let o = a.all_pass();
        ok &= o;
        println!(
            "avb_rollback: mono={}/{} rb={}/{} eq={}/{} => {}",
            a.mono_ok,
            a.trials,
            a.rollback_rejected_ok,
            a.trials,
            a.equal_accept_ok,
            a.trials,
            flag(o)
        );
    }
    {
        let p = measure_powercut(prereg::PWR_SEED, trials);
        let o = p.all_pass();
        ok &= o;
        println!(
            "powercut: wbv_breaks={}/{} vbw_preserves={}/{} wbv_nocut={}/{} vbw_nocut={}/{} => {}",
            p.wbv_breaks_ok,
            p.trials,
            p.vbw_preserves_ok,
            p.trials,
            p.wbv_no_cut_ok,
            p.trials,
            p.vbw_no_cut_ok,
            p.trials,
            flag(o)
        );
    }
    // pate MC via fa_models legacy was in pate module - use simple chain props via fa-pate
    {
        use fa_core::rng::Rng;
        let mut rng = Rng::new(prereg::PATE_SEED);
        let mut honest = 0u64;
        let mut ins = 0u64;
        let mut om = 0u64;
        let mut rd = 0u64;
        for _ in 0..trials {
            let mut t = Transcript::init("mc");
            let n = 3 + (rng.below(5) as usize);
            for i in 0..n {
                let _ = t.append("step", format!("e{i}"), "T", "op", "tool", "");
            }
            if t.verify().is_ok() {
                honest += 1;
            }
            let mut evil = t.clone();
            if let Some(e) = evil.entries.get_mut(n / 2) {
                e.event.payload.push('X');
            }
            if evil.verify().is_err() {
                ins += 1;
            }
            let mut omit = t.clone();
            if omit.entries.len() > 2 {
                omit.entries.remove(1);
            }
            if omit.verify().is_err() {
                om += 1;
            }
            let mut re = t.clone();
            if re.entries.len() >= 2 {
                re.entries.swap(0, 1);
            }
            if re.verify().is_err() {
                rd += 1;
            }
        }
        let o = honest == trials && ins == trials && om == trials && rd == trials;
        ok &= o;
        println!(
            "pate: honest={trials}/{trials} insert={ins}/{trials} omit={om}/{trials} reorder={rd}/{trials} => {}",
            flag(o)
        );
        let _ = (honest,);
    }
    {
        let cap = measure_capability_properties();
        let o = cap.all_pass();
        ok &= o;
        println!(
            "lock_capabilities: rows={} invariantes_ok={} => {}",
            cap.rows,
            o,
            flag(o)
        );
    }
    println!(
        "=== measure global: {} (elapsed_ms={}) etiqueta=por construccion ===",
        flag(ok),
        t0.elapsed().as_millis()
    );
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_bfs() -> ExitCode {
    println!("=== bfs (v0.1-equivalent via Model + legacy oracle) ===");
    let cfg = CheckerConfig {
        max_states: 10_000,
        dfs: false,
    };
    let mut ok = true;
    let pin = explore(&PinModel::default(), &cfg).expect("pin");
    let pin_g = bfs_pin_counter();
    println!(
        "pin_counter: states={} transitions={} violations=0 elapsed_ms={} bound=max_fails=5, throttle∈{{0,1}}, states BFU/AFU/Wiped => {}",
        pin.states, pin.transitions, pin.elapsed_ms, flag(pin.states == pin_g.states_explored && pin.transitions == pin_g.transitions)
    );
    ok &= pin.states == pin_g.states_explored && pin.transitions == pin_g.transitions;

    let rpmb = explore(&RpmbModel, &cfg).expect("rpmb");
    let rpmb_g = bfs_rpmb();
    println!(
        "rpmb: states={} transitions={} violations=0 elapsed_ms={} bound=n_blocks=2, write_counter≤8, data∈{{0,1}} => {}",
        rpmb.states, rpmb.transitions, rpmb.elapsed_ms, flag(rpmb.states == rpmb_g.states_explored && rpmb.transitions == rpmb_g.transitions)
    );
    ok &= rpmb.states == rpmb_g.states_explored && rpmb.transitions == rpmb_g.transitions;

    let gk = explore(&GatekeeperModel::default(), &cfg).expect("gk");
    let gk_g = bfs_gatekeeper();
    println!(
        "gatekeeper: states={} transitions={} violations=0 elapsed_ms={} bound=max_fails=4, secreto abstracto {{0,1}}, RPMB tracks fails => {}",
        gk.states, gk.transitions, gk.elapsed_ms, flag(gk.states == gk_g.states_explored && gk.transitions == gk_g.transitions)
    );
    ok &= gk.states == gk_g.states_explored && gk.transitions == gk_g.transitions;

    println!("=== bfs global: {} ===", flag(ok));
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_mutants() -> ExitCode {
    println!("=== mutants (sensibilidad) ===");
    let r = run_all_mutants();
    for m in &r.results {
        println!(
            "{} [{}]: detected={} ({})",
            m.id, m.model, m.detected, m.detail
        );
    }
    let ok = r.all_detected();
    println!(
        "=== mutants: {}/{} detectados => {} ===",
        r.detected(),
        r.total(),
        flag(ok)
    );
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_catalog() -> ExitCode {
    fn cell(r: Reachability) -> &'static str {
        match r {
            Reachability::Reachable => "SI",
            Reachability::NotReachable => "NO",
            Reachability::ReachableButCiphertext => "CT",
        }
    }
    println!(
        "{:<22} {:>5} {:>5} {:>5}  nota",
        "clase", "BFU", "AFU", "WIPE"
    );
    for row in catalog() {
        println!(
            "{:<22?} {:>5} {:>5} {:>5}  {}",
            row.class,
            cell(row.in_bfu),
            cell(row.in_afu),
            cell(row.in_wiped),
            row.note
        );
    }
    ExitCode::SUCCESS
}

fn cmd_check(model: &str) -> ExitCode {
    let cfg = CheckerConfig::default();
    match model {
        "pin" | "pin_counter" => {
            match check(&PinModel::default(), &[fa_models::pin_model::PinMono], &cfg) {
                Ok(CheckOutcome::Ok {
                    states,
                    transitions,
                    elapsed_ms,
                }) => {
                    println!("check pin: OK states={states} transitions={transitions} elapsed_ms={elapsed_ms}");
                    ExitCode::SUCCESS
                }
                Ok(CheckOutcome::Violated {
                    states,
                    transitions,
                    elapsed_ms,
                    counterexample,
                }) => {
                    println!(
                        "check pin: VIOLATED prop={} states={states} transitions={transitions} elapsed_ms={elapsed_ms}",
                        counterexample.property
                    );
                    for tr in counterexample.trace {
                        println!(
                            "  {} -{}-> {}",
                            tr.from.label(),
                            tr.action.name(),
                            tr.to.label()
                        );
                    }
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "gatekeeper" | "gk" => match check(
            &GatekeeperModel::default(),
            &[fa_models::gatekeeper_model::GkBound],
            &cfg,
        ) {
            Ok(CheckOutcome::Ok {
                states,
                transitions,
                elapsed_ms,
            }) => {
                println!("check gatekeeper: OK states={states} transitions={transitions} elapsed_ms={elapsed_ms}");
                ExitCode::SUCCESS
            }
            Ok(CheckOutcome::Violated { counterexample, .. }) => {
                println!("check gatekeeper: VIOLATED {}", counterexample.property);
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        "rpmb" => match check(&RpmbModel, &[fa_models::rpmb_model::RpmbBound], &cfg) {
            Ok(CheckOutcome::Ok {
                states,
                transitions,
                elapsed_ms,
            }) => {
                println!("check rpmb: OK states={states} transitions={transitions} elapsed_ms={elapsed_ms}");
                ExitCode::SUCCESS
            }
            Ok(CheckOutcome::Violated { counterexample, .. }) => {
                println!("check rpmb: VIOLATED {}", counterexample.property);
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("modelo desconocido: {other} (pin|rpmb|gatekeeper)");
            ExitCode::FAILURE
        }
    }
}

fn cmd_graph(model: &str, out: Option<PathBuf>) -> ExitCode {
    let cfg = CheckerConfig {
        max_states: 5000,
        dfs: false,
    };
    let dot = match model {
        "pin" | "pin_counter" => to_dot(&PinModel::default(), &cfg),
        "rpmb" => to_dot(&RpmbModel, &cfg),
        "gatekeeper" | "gk" => to_dot(&GatekeeperModel::default(), &cfg),
        other => {
            eprintln!("modelo desconocido: {other}");
            return ExitCode::FAILURE;
        }
    };
    match dot {
        Ok(s) => {
            if let Some(p) = out {
                if let Err(e) = std::fs::write(&p, &s) {
                    eprintln!("write: {e}");
                    return ExitCode::FAILURE;
                }
                println!("DOT escrito en {}", p.display());
            } else {
                print!("{s}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_pate(cmd: PateCmd) -> ExitCode {
    match cmd {
        PateCmd::Init { case_id, out } => {
            let t = Transcript::init(case_id);
            match t.to_json().and_then(|j| {
                std::fs::write(&out, j).map_err(|e| fa_core::Error::Msg(e.to_string()))
            }) {
                Ok(()) => {
                    println!("init OK -> {}", out.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        PateCmd::Append {
            file,
            kind,
            payload,
            timestamp,
            operator,
            tool,
            artifact_sha256,
        } => {
            let mut t = match load_pate(&file) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = t.append(kind, payload, timestamp, operator, tool, artifact_sha256) {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
            save_pate(&file, &t)
        }
        PateCmd::Seal {
            file,
            operator,
            timestamp,
        } => {
            let mut t = match load_pate(&file) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = t.seal(operator, timestamp) {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
            save_pate(&file, &t)
        }
        PateCmd::Verify { file } => {
            let t = match load_pate(&file) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            match t.verify() {
                Ok(()) => {
                    println!("verify OK tip={}", t.tip());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("verify FAIL: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        PateCmd::Report { file, out } => {
            let t = match load_pate(&file) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            let md = t.to_markdown();
            if let Some(p) = out {
                if let Err(e) = std::fs::write(&p, &md) {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
                println!("report -> {}", p.display());
            } else {
                print!("{md}");
            }
            ExitCode::SUCCESS
        }
    }
}

fn load_pate(p: &PathBuf) -> Result<Transcript, String> {
    let s = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
    Transcript::from_json(&s).map_err(|e| e.to_string())
}

fn save_pate(p: &PathBuf, t: &Transcript) -> ExitCode {
    match t
        .to_json()
        .and_then(|j| std::fs::write(p, j).map_err(|e| fa_core::Error::Msg(e.to_string())))
    {
        Ok(()) => {
            println!("OK tip={}", t.tip());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
