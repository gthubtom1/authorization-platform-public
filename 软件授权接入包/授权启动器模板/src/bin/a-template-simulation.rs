use std::env;

use authorization_a_template::{
    run_session_matrix, run_simulation, sample_manifest, sample_profile, SimulationScenario,
    SESSION_SIMULATION_VERSION, TEMPLATE_SIMULATION_VERSION,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let requested = args
        .windows(2)
        .find(|pair| pair[0] == "--scenario")
        .map(|pair| pair[1].as_str());

    let scenarios: Vec<SimulationScenario> = match requested {
        Some(value) => vec![SimulationScenario::from_str(value).ok_or_else(|| {
            format!(
                "unknown scenario {value}; expected one of: {}",
                SimulationScenario::ALL
                    .iter()
                    .map(|scenario| scenario.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?],
        None => SimulationScenario::ALL.to_vec(),
    };

    let manifest = sample_manifest();
    let profile = sample_profile(&manifest);
    println!("simulation protocol: {TEMPLATE_SIMULATION_VERSION}");
    println!("product: {}", manifest.product_id);
    for scenario in scenarios {
        let report = run_simulation(manifest.clone(), profile.clone(), scenario, 1_800_000_100)?;
        let error = report.boundary_error.as_deref().unwrap_or("none");
        println!(
            "[{}] lifecycle={} ui={}/{} launch={} adapter={} core={} replay={} raw_credential={} error={}",
            report.scenario.as_str(),
            report.lifecycle_state.as_str(),
            report.ui_state.screen.as_str(),
            report.ui_state.authorization.as_str(),
            report.launch_requested,
            report.adapter_granted,
            report.core_outcome.as_str(),
            report.idempotent_replay,
            report.raw_credential_exposed,
            error
        );
    }

    println!("session protocol: {SESSION_SIMULATION_VERSION}");
    println!("single machine stays open after verify; core expiry is the card");
    println!("two-machine same card (after single-machine):");
    println!("  displace on  -> old computer must stop");
    println!("  displace off -> new computer must not enter");
    for report in run_session_matrix(1_800_000_100) {
        println!(
            "[{}] passed={} {}",
            report.scenario.as_str(),
            report.passed,
            report.detail
        );
        if !report.passed {
            return Err(format!(
                "session scenario {} failed: {}",
                report.scenario.as_str(),
                report.detail
            )
            .into());
        }
    }
    Ok(())
}
