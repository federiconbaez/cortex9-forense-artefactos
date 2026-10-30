//! Bench like-for-like: BFS v0.1 legacy vs v0.2 Model; MC 1e6 por modelo.
use fa_checker::{explore, CheckerConfig};
use fa_core::prereg;
use fa_models::apple_dp::measure_apple_dp;
use fa_models::avb_rollback::measure_avb;
use fa_models::fbe_keys::measure_fbe;
use fa_models::gatekeeper::measure_gatekeeper_properties;
use fa_models::gatekeeper_model::GatekeeperModel;
use fa_models::inactivity::measure_inactivity;
use fa_models::legacy_bfs::{bfs_gatekeeper, bfs_pin_counter, bfs_rpmb};
use fa_models::pin_counter::measure_pin_properties;
use fa_models::pin_model::PinModel;
use fa_models::powercut::measure_powercut;
use fa_models::rpmb::measure_rpmb_properties;
use fa_models::rpmb_model::RpmbModel;
use fa_models::weaver::measure_weaver;
use std::time::Instant;

fn main() {
    println!("=== like-for-like bench ===");
    println!("metas preregistro >=50k st/s fueron conservadoras; ratio v02/v01 es la cifra util");
    let cfg = CheckerConfig {
        max_states: 100_000,
        dfs: false,
    };
    let rounds = 2000u64;

    macro_rules! bfs_pair {
        ($name:expr, $gold:expr, $model:expr) => {{
            let t0 = Instant::now();
            let mut st = 0u64;
            for _ in 0..rounds {
                st += $gold().states_explored;
            }
            let ms01 = t0.elapsed().as_secs_f64() * 1000.0;
            let sps01 = st as f64 / (ms01 / 1000.0);
            let t1 = Instant::now();
            let mut st2 = 0u64;
            for _ in 0..rounds {
                st2 += explore($model, &cfg).unwrap().states;
            }
            let ms02 = t1.elapsed().as_secs_f64() * 1000.0;
            let sps02 = st2 as f64 / (ms02 / 1000.0);
            let g = $gold();
            let r = explore($model, &cfg).unwrap();
            println!(
                "bfs_{}: v01={}/{} v02={}/{} match={} v01_st_s={:.0} v02_st_s={:.0} ratio={:.3}",
                $name,
                g.states_explored,
                g.transitions,
                r.states,
                r.transitions,
                g.states_explored == r.states && g.transitions == r.transitions,
                sps01,
                sps02,
                if sps01 > 0.0 { sps02 / sps01 } else { 0.0 }
            );
        }};
    }

    bfs_pair!("pin", bfs_pin_counter, &PinModel::default());
    bfs_pair!("rpmb", bfs_rpmb, &RpmbModel);
    bfs_pair!("gatekeeper", bfs_gatekeeper, &GatekeeperModel::default());

    const N: u64 = 1_000_000;
    println!("=== MC {N} (shared measure_* path; same hardware) ===");
    macro_rules! mc {
        ($name:expr, $call:expr) => {{
            let t0 = Instant::now();
            let ok = $call;
            println!(
                "mc_{}_1e6_ms={} all_pass={}",
                $name,
                t0.elapsed().as_millis(),
                ok
            );
        }};
    }
    mc!(
        "pin",
        measure_pin_properties(prereg::PIN_SEED, N).all_pass()
    );
    mc!(
        "rpmb",
        measure_rpmb_properties(prereg::RPMB_SEED, N).all_pass()
    );
    mc!(
        "gatekeeper",
        measure_gatekeeper_properties(prereg::GK_SEED, N).all_pass()
    );
    mc!("weaver", measure_weaver(prereg::WEAVER_SEED, N).all_pass());
    mc!("fbe", measure_fbe(prereg::FBE_SEED, N).all_pass());
    mc!("apple_dp", measure_apple_dp(prereg::ADP_SEED, N).all_pass());
    mc!(
        "inactivity",
        measure_inactivity(prereg::IDLE_SEED, N).all_pass()
    );
    mc!("avb", measure_avb(prereg::AVB_SEED, N).all_pass());
    mc!("powercut", measure_powercut(prereg::PWR_SEED, N).all_pass());
}
