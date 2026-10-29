//! CLI de medición. Reproduce los umbrales preregistrados.
//!
//! Uso:
//!   forense-artefactos measure
//!   forense-artefactos catalog

use forense_artefactos::gatekeeper::measure_gatekeeper_properties;
use forense_artefactos::lock_capabilities::{catalog, measure_capability_properties, Reachability};
use forense_artefactos::pin_counter::measure_pin_properties;
use forense_artefactos::prereg;
use forense_artefactos::rpmb::measure_rpmb_properties;
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("measure") => cmd_measure(),
        Some("catalog") => cmd_catalog(),
        Some("help") | Some("-h") | Some("--help") | None => {
            eprintln!(
                "uso: forense-artefactos <measure|catalog>\n\
                 measure  — corre mediciones preregistradas y sale 0 solo si todos los umbrales se cumplen\n\
                 catalog  — imprime la tabla de capacidades BFU/AFU/wipe"
            );
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("comando desconocido: {other}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_measure() -> ExitCode {
    println!("=== preregistro ===");
    println!(
        "PIN_SEED={:#x} trials={}",
        prereg::PIN_SEED,
        prereg::PIN_TRIALS
    );
    println!(
        "RPMB_SEED={:#x} trials={}",
        prereg::RPMB_SEED,
        prereg::RPMB_TRIALS
    );
    println!(
        "GK_SEED={:#x} trials={}",
        prereg::GK_SEED,
        prereg::GK_TRIALS
    );

    let pin = measure_pin_properties(prereg::PIN_SEED, prereg::PIN_TRIALS);
    println!("=== pin_counter (por construcción) ===");
    println!(
        "trials={} mono={}/{} throttle={}/{} wipe={}/{} reset={}/{} bfu_afu={}/{} ce_only_afu={}/{}",
        pin.trials,
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
        pin.trials
    );
    let pin_ok = pin.all_pass();
    println!(
        "umbral PIN 100/100 en 6 propiedades: {}",
        if pin_ok { "CUMPLIDO" } else { "NO CUMPLIDO" }
    );

    let rpmb = measure_rpmb_properties(prereg::RPMB_SEED, prereg::RPMB_TRIALS);
    println!("=== rpmb (por construcción) ===");
    println!(
        "trials={} mono={}/{} bad_mac={}/{} replay={}/{} honest={}/{} roundtrip={}/{}",
        rpmb.trials,
        rpmb.mono_ok,
        rpmb.trials,
        rpmb.bad_mac_rejected,
        rpmb.trials,
        rpmb.replay_rejected,
        rpmb.trials,
        rpmb.honest_write_ok,
        rpmb.trials,
        rpmb.read_roundtrip_ok,
        rpmb.trials
    );
    let rpmb_ok = rpmb.all_pass();
    println!(
        "umbral RPMB 100/100 en 5 propiedades: {}",
        if rpmb_ok { "CUMPLIDO" } else { "NO CUMPLIDO" }
    );

    let gk = measure_gatekeeper_properties(prereg::GK_SEED, prereg::GK_TRIALS);
    println!("=== gatekeeper (por construcción) ===");
    println!(
        "trials={} enroll={}/{} wrong={}/{} rpmb_tracks={}/{} wipe={}/{} throttle={}/{}",
        gk.trials,
        gk.enroll_verify_ok,
        gk.trials,
        gk.wrong_rejected,
        gk.trials,
        gk.rpmb_tracks_fails,
        gk.trials,
        gk.wipe_denies,
        gk.trials,
        gk.throttle_respected,
        gk.trials
    );
    let gk_ok = gk.all_pass();
    println!(
        "umbral GK 100/100 en 5 propiedades: {}",
        if gk_ok { "CUMPLIDO" } else { "NO CUMPLIDO" }
    );

    let cap = measure_capability_properties();
    println!("=== lock_capabilities ===");
    println!(
        "rows={} ce_bfu_afu={} nand_ct={} wipe_clears={} rpmb_persists={} wellformed={}",
        cap.rows,
        cap.ce_bfu_afu_ok,
        cap.nand_ciphertext_ok,
        cap.wipe_clears_user_ok,
        cap.rpmb_persists_ok,
        cap.catalog_wellformed_ok
    );
    let cap_ok = cap.all_pass();
    println!(
        "umbral capacidades (5 invariantes): {}",
        if cap_ok { "CUMPLIDO" } else { "NO CUMPLIDO" }
    );

    let all = pin_ok && rpmb_ok && gk_ok && cap_ok;
    println!(
        "=== resultado global: {} ===",
        if all { "CUMPLIDO" } else { "NO CUMPLIDO" }
    );
    if all {
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
    println!("leyenda: SI=alcanzable  NO=no alcanzable  CT=alcanzable pero ciphertext");
    ExitCode::SUCCESS
}
