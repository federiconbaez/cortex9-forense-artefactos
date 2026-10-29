//! CLI de medición a escala.
//!
//!   forense-artefactos measure [--mode ci|full]
//!   forense-artefactos bfs
//!   forense-artefactos mutants
//!   forense-artefactos catalog
//!   forense-artefactos all [--mode ci|full]

use forense_artefactos::apple_dp::measure_apple_dp;
use forense_artefactos::avb_rollback::measure_avb;
use forense_artefactos::fbe_keys::measure_fbe;
use forense_artefactos::gatekeeper::measure_gatekeeper_properties;
use forense_artefactos::inactivity::measure_inactivity;
use forense_artefactos::lock_capabilities::{catalog, measure_capability_properties, Reachability};
use forense_artefactos::model_check::{bfs_gatekeeper, bfs_pin_counter, bfs_rpmb};
use forense_artefactos::mutants::run_all_mutants;
use forense_artefactos::pate::measure_pate;
use forense_artefactos::pin_counter::measure_pin_properties;
use forense_artefactos::powercut::measure_powercut;
use forense_artefactos::prereg;
use forense_artefactos::rpmb::measure_rpmb_properties;
use forense_artefactos::weaver::measure_weaver;
use std::env;
use std::process::ExitCode;
use std::time::Instant;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    let mode = args
        .iter()
        .position(|a| a == "--mode")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("ci");
    let trials = match mode {
        "full" => prereg::FULL_TRIALS,
        _ => prereg::CI_TRIALS,
    };

    match cmd {
        "measure" => cmd_measure(mode, trials),
        "bfs" => cmd_bfs(),
        "mutants" => cmd_mutants(),
        "catalog" => cmd_catalog(),
        "all" => {
            let a = cmd_measure(mode, trials);
            let b = cmd_bfs();
            let c = cmd_mutants();
            if a == ExitCode::SUCCESS && b == ExitCode::SUCCESS && c == ExitCode::SUCCESS {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "help" | "-h" | "--help" => {
            eprintln!(
                "uso: forense-artefactos <measure|bfs|mutants|catalog|all> [--mode ci|full]\n\
                 measure  — Monte-Carlo preregistrado (ci=1e4, full=1e7)\n\
                 bfs      — model checking exhaustivo acotado\n\
                 mutants  — sensibilidad del checker (7 mutantes)\n\
                 catalog  — tabla BFU/AFU/wipe\n\
                 all      — measure + bfs + mutants"
            );
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("comando desconocido: {other}");
            ExitCode::FAILURE
        }
    }
}

fn flag(ok: bool) -> &'static str {
    if ok {
        "CUMPLIDO"
    } else {
        "NO CUMPLIDO"
    }
}

fn cmd_measure(mode: &str, trials: u64) -> ExitCode {
    println!("=== measure mode={mode} trials={trials} ===");
    let t0 = Instant::now();
    let mut all_ok = true;

    let pin = measure_pin_properties(prereg::PIN_SEED, trials);
    let pin_ok = pin.all_pass();
    all_ok &= pin_ok;
    println!(
        "pin_counter: mono={}/{} throttle={}/{} wipe={}/{} reset={}/{} bfu_afu={}/{} ce={}/{} => {}",
        pin.mono_ok,
        pin.trials,
        pin.throttle_ok,
        pin.trials,
        pin.wipe_ok,
        pin.trials,
        pin.success_resets_ok,
        pin.trials,
        pin.bfu_to_afu_ok,
        pin.trials,
        pin.ce_only_afu_ok,
        pin.trials,
        flag(pin_ok)
    );

    let rpmb = measure_rpmb_properties(prereg::RPMB_SEED, trials);
    let rpmb_ok = rpmb.all_pass();
    all_ok &= rpmb_ok;
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
        flag(rpmb_ok)
    );

    let gk = measure_gatekeeper_properties(prereg::GK_SEED, trials);
    let gk_ok = gk.all_pass();
    all_ok &= gk_ok;
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
        flag(gk_ok)
    );

    let w = measure_weaver(prereg::WEAVER_SEED, trials);
    let w_ok = w.all_pass();
    all_ok &= w_ok;
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
        flag(w_ok)
    );

    let fbe = measure_fbe(prereg::FBE_SEED, trials);
    let fbe_ok = fbe.all_pass();
    all_ok &= fbe_ok;
    println!(
        "fbe_keys: de={}/{} ce_afu={}/{} evict={}/{} wipe={}/{} => {}",
        fbe.de_after_boot_ok,
        fbe.trials,
        fbe.ce_only_afu_ok,
        fbe.trials,
        fbe.eviction_ok,
        fbe.trials,
        fbe.wipe_clears_ok,
        fbe.trials,
        flag(fbe_ok)
    );

    let adp = measure_apple_dp(prereg::ADP_SEED, trials);
    let adp_ok = adp.all_pass();
    all_ok &= adp_ok;
    println!(
        "apple_dp: bfu_d={}/{} afu={}/{} relock={}/{} => {}",
        adp.bfu_only_d_ok,
        adp.trials,
        adp.afu_all_ok,
        adp.trials,
        adp.relock_class_a_denied_ok,
        adp.trials,
        flag(adp_ok)
    );

    let idle = measure_inactivity(prereg::IDLE_SEED, trials);
    let idle_ok = idle.all_pass();
    all_ok &= idle_ok;
    println!(
        "inactivity: timeout={}/{} touch={}/{} evict={}/{} => {}",
        idle.timeout_triggers_ok,
        idle.trials,
        idle.touch_resets_ok,
        idle.trials,
        idle.ce_evicted_ok,
        idle.trials,
        flag(idle_ok)
    );

    let avb = measure_avb(prereg::AVB_SEED, trials);
    let avb_ok = avb.all_pass();
    all_ok &= avb_ok;
    println!(
        "avb_rollback: mono={}/{} rb={}/{} eq={}/{} => {}",
        avb.mono_ok,
        avb.trials,
        avb.rollback_rejected_ok,
        avb.trials,
        avb.equal_accept_ok,
        avb.trials,
        flag(avb_ok)
    );

    let pwr = measure_powercut(prereg::PWR_SEED, trials);
    let pwr_ok = pwr.all_pass();
    all_ok &= pwr_ok;
    println!(
        "powercut: wbv_breaks={}/{} vbw_preserves={}/{} wbv_nocut={}/{} vbw_nocut={}/{} => {}",
        pwr.wbv_breaks_ok,
        pwr.trials,
        pwr.vbw_preserves_ok,
        pwr.trials,
        pwr.wbv_no_cut_ok,
        pwr.trials,
        pwr.vbw_no_cut_ok,
        pwr.trials,
        flag(pwr_ok)
    );

    let pate = measure_pate(prereg::PATE_SEED, trials);
    let pate_ok = pate.all_pass();
    all_ok &= pate_ok;
    println!(
        "pate: honest={}/{} insert={}/{} omit={}/{} reorder={}/{} => {}",
        pate.honest_ok,
        pate.trials,
        pate.detect_insert_ok,
        pate.trials,
        pate.detect_omit_ok,
        pate.trials,
        pate.detect_reorder_ok,
        pate.trials,
        flag(pate_ok)
    );

    let cap = measure_capability_properties();
    let cap_ok = cap.all_pass();
    all_ok &= cap_ok;
    println!(
        "lock_capabilities: rows={} invariantes_ok={} => {}",
        cap.rows,
        cap_ok,
        flag(cap_ok)
    );

    let ms = t0.elapsed().as_millis();
    println!(
        "=== measure global: {} (elapsed_ms={ms}) etiqueta=por construccion ===",
        flag(all_ok)
    );
    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_bfs() -> ExitCode {
    println!("=== bfs (limites preregistrados) ===");
    let mut ok = true;
    for r in [bfs_pin_counter(), bfs_rpmb(), bfs_gatekeeper()] {
        let pass = r.ok();
        ok &= pass;
        println!(
            "{}: states={} transitions={} violations={} elapsed_ms={} bound={} => {}",
            r.name,
            r.states_explored,
            r.transitions,
            r.violations,
            r.elapsed_ms,
            r.bound_note,
            flag(pass)
        );
    }
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
        println!("{}: detected={} ({})", m.id, m.detected, m.detail);
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
