use atf_core::{validate_lifecycle_transition, IntentLifecycleState as State};

const ALLOWED: &[(State, State)] = &[
    (State::Received, State::IdentityVerified),
    (State::Received, State::IdentityRejected),
    (State::IdentityVerified, State::PolicyEvaluated),
    (State::PolicyEvaluated, State::RiskEvaluated),
    (State::RiskEvaluated, State::SimulationCompleted),
    (State::SimulationCompleted, State::DecidedPermit),
    (State::SimulationCompleted, State::DecidedReview),
    (State::SimulationCompleted, State::DecidedDeny),
    (State::SimulationCompleted, State::DecidedError),
    (State::DecidedPermit, State::ApprovalPending),
    (State::DecidedPermit, State::ExecutionAuthorized),
    (State::DecidedReview, State::ApprovalPending),
    (State::ApprovalPending, State::Approved),
    (State::ApprovalPending, State::Rejected),
    (State::Approved, State::ExecutionAuthorized),
    (State::ExecutionAuthorized, State::ExecutionSubmitted),
    (State::ExecutionSubmitted, State::ExecutionConfirmed),
    (State::ExecutionSubmitted, State::ExecutionFailed),
    (State::ExecutionConfirmed, State::SettlementVerified),
    (State::ExecutionConfirmed, State::ReconciliationFailed),
    (State::Received, State::Expired),
    (State::Received, State::Cancelled),
    (State::IdentityVerified, State::Expired),
    (State::IdentityVerified, State::Cancelled),
    (State::PolicyEvaluated, State::Expired),
    (State::PolicyEvaluated, State::Cancelled),
    (State::RiskEvaluated, State::Expired),
    (State::RiskEvaluated, State::Cancelled),
    (State::SimulationCompleted, State::Expired),
    (State::SimulationCompleted, State::Cancelled),
    (State::DecidedPermit, State::Expired),
    (State::DecidedPermit, State::Cancelled),
    (State::DecidedReview, State::Expired),
    (State::DecidedReview, State::Cancelled),
    (State::ApprovalPending, State::Expired),
    (State::ApprovalPending, State::Cancelled),
    (State::Approved, State::Expired),
    (State::Approved, State::Cancelled),
    (State::ExecutionAuthorized, State::Expired),
    (State::ExecutionAuthorized, State::Cancelled),
];

#[test]
fn transition_table_allows_exactly_the_documented_pairs() {
    for from in State::ALL {
        for to in State::ALL {
            let expected = ALLOWED.contains(&(from, to));
            assert_eq!(
                validate_lifecycle_transition(from, to).is_ok(),
                expected,
                "unexpected transition result for {from} -> {to}"
            );
        }
    }
}

#[test]
fn every_terminal_state_rejects_every_possible_successor() {
    let terminal = [
        State::IdentityRejected,
        State::DecidedDeny,
        State::DecidedError,
        State::Rejected,
        State::ExecutionFailed,
        State::SettlementVerified,
        State::ReconciliationFailed,
        State::Expired,
        State::Cancelled,
    ];

    for state in terminal {
        assert!(state.is_terminal(), "{state} must be terminal");
        for successor in State::ALL {
            assert!(
                validate_lifecycle_transition(state, successor).is_err(),
                "terminal state {state} advanced to {successor}"
            );
        }
    }
}

#[test]
fn nonterminal_states_are_not_mislabeled_terminal() {
    for state in State::ALL {
        let has_successor = ALLOWED.iter().any(|(from, _)| *from == state);
        assert_eq!(
            state.is_terminal(),
            !has_successor,
            "terminal classification drifted for {state}"
        );
    }
}

#[test]
fn lifecycle_states_have_stable_screaming_snake_case_wire_names() {
    assert_eq!(
        serde_json::to_string(&State::SimulationCompleted).unwrap(),
        r#""SIMULATION_COMPLETED""#
    );
    assert_eq!(
        serde_json::from_str::<State>(r#""DECIDED_ERROR""#).unwrap(),
        State::DecidedError
    );
    assert!(serde_json::from_str::<State>(r#""UNKNOWN""#).is_err());
}
