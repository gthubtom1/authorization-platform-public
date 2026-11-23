use authorization_a_template::{
    run_session_matrix, run_simulation, sample_manifest, sample_profile, LicenseState,
    SessionScenario, SimulationCoreOutcome, SimulationScenario,
};

#[test]
fn simulation_covers_success_failure_and_core_handoff_paths() {
    let manifest = sample_manifest();
    let profile = sample_profile(&manifest);

    for scenario in SimulationScenario::ALL {
        let report =
            run_simulation(manifest.clone(), profile.clone(), *scenario, 1_800_000_100).unwrap();

        match scenario {
            SimulationScenario::Active => {
                assert_eq!(report.lifecycle_state, LicenseState::Active);
                assert!(report.launch_requested);
                assert!(report.adapter_granted);
                assert_eq!(report.core_outcome, SimulationCoreOutcome::Started);
                assert!(report.idempotent_replay);
            }
            SimulationScenario::Grace => {
                assert_eq!(report.lifecycle_state, LicenseState::Grace);
                assert!(report.launch_requested);
                assert!(report.adapter_granted);
                assert_eq!(report.core_outcome, SimulationCoreOutcome::Started);
                assert!(report.idempotent_replay);
            }
            SimulationScenario::Expired
            | SimulationScenario::Revoked
            | SimulationScenario::Unavailable
            | SimulationScenario::DeviceMismatch => {
                assert!(!report.launch_requested);
                assert!(!report.adapter_granted);
                assert_eq!(report.core_outcome, SimulationCoreOutcome::NotAttempted);
                assert!(report.boundary_error.is_some());
            }
            SimulationScenario::CoreMissing => {
                assert!(report.launch_requested);
                assert!(report.adapter_granted);
                assert_eq!(report.core_outcome, SimulationCoreOutcome::Missing);
            }
            SimulationScenario::CoreStartFailed => {
                assert!(report.launch_requested);
                assert!(report.adapter_granted);
                assert_eq!(report.core_outcome, SimulationCoreOutcome::StartFailed);
            }
        }
        assert!(!report.raw_credential_exposed);
    }
}

#[test]
fn simulation_profile_is_product_bound() {
    let mut manifest = sample_manifest();
    manifest.product_id = "other-product".to_string();
    let profile = sample_profile(&sample_manifest());

    assert!(run_simulation(manifest, profile, SimulationScenario::Active, 1_800_000_100).is_err());
}

#[test]
fn simulation_covers_two_machine_same_card_session_paths() {
    let reports = run_session_matrix(1_800_000_100);
    assert_eq!(reports.len(), SessionScenario::ALL.len());
    for report in reports {
        assert!(
            report.passed,
            "{} failed: {}",
            report.scenario.as_str(),
            report.detail
        );
    }
}
