#![cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Symbol};

use crate::{WaveOracle, WaveOracleClient};

fn setup() -> (Env, WaveOracleClient<'static>, BytesN<32>) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, WaveOracle);
    let client = WaveOracleClient::new(&env, &id);
    let repo_hash = BytesN::from_array(&env, &[1u8; 32]);
    (env, client, repo_hash)
}

#[test]
fn test_below_threshold() {
    let (env, client, repo_hash) = setup();
    let admin = Address::generate(&env);
    let reporter = Address::generate(&env);
    client.init(&admin, &2);
    client.add_reporter(&reporter);
    assert!(!client.verify_merge(&reporter, &Symbol::new(&env, "alice"), &1, &repo_hash));
    assert_eq!(client.get_confirmations(&1, &repo_hash), 1);
}

#[test]
fn test_multi_sig_threshold() {
    let (env, client, repo_hash) = setup();
    let admin = Address::generate(&env);
    let (r1, r2) = (Address::generate(&env), Address::generate(&env));
    client.init(&admin, &2);
    client.add_reporter(&r1);
    client.add_reporter(&r2);
    client.verify_merge(&r1, &Symbol::new(&env, "alice"), &42, &repo_hash);
    assert!(client.verify_merge(&r2, &Symbol::new(&env, "alice"), &42, &repo_hash));
    assert!(client.is_merged(&42, &repo_hash));
}

#[test]
fn test_replay_prevention() {
    let (env, client, repo_hash) = setup();
    let admin = Address::generate(&env);
    let reporter = Address::generate(&env);
    client.init(&admin, &1);
    client.add_reporter(&reporter);
    assert!(client.verify_merge(&reporter, &Symbol::new(&env, "bob"), &7, &repo_hash));
    // Second call is idempotent
    assert!(client.verify_merge(&reporter, &Symbol::new(&env, "bob"), &7, &repo_hash));
    assert_eq!(client.get_confirmations(&7, &repo_hash), 1);
}

#[test]
fn test_double_vote_ignored() {
    let (env, client, repo_hash) = setup();
    let admin = Address::generate(&env);
    let reporter = Address::generate(&env);
    client.init(&admin, &3);
    client.add_reporter(&reporter);
    client.verify_merge(&reporter, &Symbol::new(&env, "carol"), &99, &repo_hash);
    client.verify_merge(&reporter, &Symbol::new(&env, "carol"), &99, &repo_hash);
    assert_eq!(client.get_confirmations(&99, &repo_hash), 1);
}

#[test]
#[should_panic(expected = "reporter not authorized")]
fn test_unauthorized_reporter() {
    let (env, client, repo_hash) = setup();
    let admin = Address::generate(&env);
    client.init(&admin, &1);
    client.verify_merge(
        &Address::generate(&env),
        &Symbol::new(&env, "eve"),
        &5,
        &repo_hash,
    );
}
