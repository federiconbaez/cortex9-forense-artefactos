use fa_checker::{explore, CheckerConfig};
use fa_core::prereg;
use fa_models::pin_counter::measure_pin_properties;
use fa_models::pin_model::PinModel;
use fa_pate::bench_verify_throughput;
use std::time::Instant;

fn main() {
    println!("=== benches v0.2 (preregistro docs/PREREGISTRO_v0.2.md) ===");
    // checker estados/s
    let cfg = CheckerConfig {
        max_states: 100_000,
        dfs: false,
    };
    let t0 = Instant::now();
    let mut total_states = 0u64;
    let rounds = 1000u64;
    for _ in 0..rounds {
        let r = explore(&PinModel::default(), &cfg).unwrap();
        total_states += r.states;
    }
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let states_per_s = (total_states as f64) / (ms / 1000.0);
    println!(
        "checker_pin_states_per_s={:.0} total_states={} rounds={} elapsed_ms={:.2} meta>=50000 => {}",
        states_per_s,
        total_states,
        rounds,
        ms,
        if states_per_s >= 50_000.0 {
            "CUMPLIDO"
        } else {
            "NO CUMPLIDO"
        }
    );

    // pate verify throughput
    for n in [100_000usize, 1_000_000] {
        let (nn, per_s) = bench_verify_throughput(n);
        println!(
            "pate_verify_n={} per_s={:.0} meta>=20000 => {}",
            nn,
            per_s,
            if per_s >= 20_000.0 {
                "CUMPLIDO"
            } else {
                "NO CUMPLIDO"
            }
        );
    }

    // pin MC 1e4 timing (compare harness)
    let t1 = Instant::now();
    let r = measure_pin_properties(prereg::PIN_SEED, 10_000);
    let ms = t1.elapsed().as_millis();
    println!(
        "pin_mc_1e4_ms={} all_pass={} (v0.1 all-models ci ~639ms reference; solo pin aqui)",
        ms,
        r.all_pass()
    );
}
