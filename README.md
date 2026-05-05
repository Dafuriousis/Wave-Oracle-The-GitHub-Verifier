# Wave Oracle: The GitHub Verifier

> A Soroban smart contract that bridges off-chain GitHub activity with on-chain state changes — trustlessly.

---

## Overview

In a decentralized contribution system, you cannot trust a user to simply *claim* they merged a pull request. Wave Oracle acts as a cryptographic oracle that receives and verifies signed data from off-chain listeners (GitHub Apps) to confirm a PR was actually merged before any points or rewards are issued on-chain.

The contract enforces a **multi-signature model**: multiple independent, whitelisted reporters must confirm the same event before it is finalized. No single reporter — even a compromised one — can unilaterally award points.

---

## Problem Statement

| Problem | Without Oracle | With Wave Oracle |
|---------|---------------|-----------------|
| Self-reporting | Users claim fake merges | Reporters verify on-chain |
| Single oracle failure | One bad actor corrupts state | M-of-N threshold required |
| Replay attacks | Same PR claimed multiple times | Event nonce `(pr_id, repo_hash)` |
| Double voting | Reporter inflates confirmations | Deduplication via `Vec<Address>` |
| Reverted code | Rewarded before revert detected | Reporter whitelist can withhold |

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     GitHub Platform                       │
│         PR #123 merged into main @ repo XYZ              │
└─────────────────────────┬────────────────────────────────┘
                          │  webhook event
                          ▼
┌──────────────────────────────────────────────────────────┐
│               Off-Chain Reporter Network                  │
│                                                           │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│   │  Reporter 1 │  │  Reporter 2 │  │  Reporter N │     │
│   │ (GitHub App)│  │ (GitHub App)│  │ (GitHub App)│     │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│          │                │                 │             │
│          └────────────────┼─────────────────┘             │
│                           │                               │
│              sign(pr_id + repo_hash + user)               │
└───────────────────────────┬──────────────────────────────┘
                            │  verify_merge(...)
                            ▼
┌──────────────────────────────────────────────────────────┐
│              Wave Oracle Contract (Soroban)               │
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Auth Layer                                         │  │
│  │  • reporter.require_auth()                          │  │
│  │  • whitelist check: Reporter(addr) → bool           │  │
│  └────────────────────────────────────────────────────┘  │
│                          │                                │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Nonce / Replay Guard                               │  │
│  │  • Merged(pr_id, repo_hash) already set? → return   │  │
│  └────────────────────────────────────────────────────┘  │
│                          │                                │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Confirmation Accumulator                           │  │
│  │  • Confirmations(pr_id, repo_hash) → Vec<Address>   │  │
│  │  • Deduplicate: reporter already in vec? → skip     │  │
│  │  • Append reporter, persist                         │  │
│  └────────────────────────────────────────────────────┘  │
│                          │                                │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Threshold Check                                    │  │
│  │  • confirmations.len() >= threshold?                │  │
│  │  • Yes → set Merged(pr_id, repo_hash) = true        │  │
│  └────────────────────────────────────────────────────┘  │
└───────────────────────────┬──────────────────────────────┘
                            │  is_merged(pr_id, repo_hash)
                            ▼
┌──────────────────────────────────────────────────────────┐
│              Downstream Contracts                         │
│   (Wave Points, Token Rewards, Reputation Tracker)        │
└──────────────────────────────────────────────────────────┘
```

---

## Storage Schema

```rust
#[contracttype]
pub enum DataKey {
    Admin,                              // Address  — contract owner
    Threshold,                          // u32      — min confirmations to finalize
    Reporter(Address),                  // bool     — whitelist entry
    Confirmations(u64, BytesN<32>),     // Vec<Address> — who confirmed this event
    Merged(u64, BytesN<32>),            // bool     — finalization flag
}
```

| Key | Type | Storage | Description |
|-----|------|---------|-------------|
| `Admin` | `Address` | Instance | Contract owner |
| `Threshold` | `u32` | Instance | Confirmations needed to finalize |
| `Reporter(addr)` | `bool` | Persistent | Whitelist entry per reporter |
| `Confirmations(pr_id, repo_hash)` | `Vec<Address>` | Persistent | Reporters who voted |
| `Merged(pr_id, repo_hash)` | `bool` | Persistent | Event finalization flag |

---

## Contract Source

### `src/lib.rs`

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Symbol, Vec};

#[contracttype]
pub enum DataKey {
    Admin,
    Threshold,
    Reporter(Address),
    Confirmations(u64, BytesN<32>),
    Merged(u64, BytesN<32>),
}

#[contract]
pub struct WaveOracle;

#[contractimpl]
impl WaveOracle {
    /// One-time initializer. Sets admin and confirmation threshold.
    pub fn init(env: Env, admin: Address, threshold: u32) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Threshold, &threshold);
    }

    pub fn add_reporter(env: Env, reporter: Address) {
        Self::require_admin(&env);
        env.storage().persistent().set(&DataKey::Reporter(reporter), &true);
    }

    pub fn remove_reporter(env: Env, reporter: Address) {
        Self::require_admin(&env);
        env.storage().persistent().remove(&DataKey::Reporter(reporter));
    }

    /// Whitelisted reporter submits a merge confirmation.
    /// Returns `true` when the threshold is reached for the first time.
    pub fn verify_merge(
        env: Env,
        reporter: Address,
        _github_user: Symbol,
        pr_id: u64,
        repo_hash: BytesN<32>,
    ) -> bool {
        reporter.require_auth();

        if !env.storage().persistent()
            .get::<_, bool>(&DataKey::Reporter(reporter.clone()))
            .unwrap_or(false)
        {
            panic!("reporter not authorized");
        }

        let merged_key = DataKey::Merged(pr_id, repo_hash.clone());
        if env.storage().persistent().get::<_, bool>(&merged_key).unwrap_or(false) {
            return true; // already finalized — idempotent
        }

        let conf_key = DataKey::Confirmations(pr_id, repo_hash.clone());
        let mut confirmations: Vec<Address> = env.storage().persistent()
            .get(&conf_key)
            .unwrap_or_else(|| Vec::new(&env));

        if confirmations.contains(&reporter) {
            return false; // double-vote guard
        }
        confirmations.push_back(reporter);
        env.storage().persistent().set(&conf_key, &confirmations);

        let threshold: u32 = env.storage().instance().get(&DataKey::Threshold).unwrap();
        if confirmations.len() >= threshold {
            env.storage().persistent().set(&merged_key, &true);
            return true;
        }

        false
    }

    pub fn is_merged(env: Env, pr_id: u64, repo_hash: BytesN<32>) -> bool {
        env.storage().persistent()
            .get::<_, bool>(&DataKey::Merged(pr_id, repo_hash))
            .unwrap_or(false)
    }

    pub fn get_confirmations(env: Env, pr_id: u64, repo_hash: BytesN<32>) -> u32 {
        let confirmations: Vec<Address> = env.storage().persistent()
            .get(&DataKey::Confirmations(pr_id, repo_hash))
            .unwrap_or_else(|| Vec::new(&env));
        confirmations.len()
    }

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
    }
}
```

---

## API Reference

### Admin Functions

#### `init(admin: Address, threshold: u32)`
One-time setup. Panics if called a second time.

```rust
// Require 2 independent reporters to confirm any merge event
client.init(&admin_address, &2);
```

#### `add_reporter(reporter: Address)`
Adds an address to the reporter whitelist. Admin-only.

```rust
client.add_reporter(&github_app_address);
```

#### `remove_reporter(reporter: Address)`
Removes an address from the whitelist. Admin-only. Existing confirmations from that reporter are not retroactively removed.

```rust
client.remove_reporter(&compromised_reporter);
```

---

### Core Function

#### `verify_merge(reporter, github_user, pr_id, repo_hash) → bool`

The primary entry point. Called by each off-chain reporter when it observes a merged PR.

| Parameter | Type | Description |
|-----------|------|-------------|
| `reporter` | `Address` | Calling reporter (must be whitelisted) |
| `github_user` | `Symbol` | GitHub username of the contributor |
| `pr_id` | `u64` | Pull request number |
| `repo_hash` | `BytesN<32>` | SHA-256 of the repository identifier |

**Returns:** `true` if this call finalized the event, `false` if still pending.

**Execution flow:**

```
reporter.require_auth()
    │
    ▼
Is reporter whitelisted?  ──No──▶  panic!("reporter not authorized")
    │ Yes
    ▼
Is Merged(pr_id, repo_hash) = true?  ──Yes──▶  return true (idempotent)
    │ No
    ▼
Is reporter already in Confirmations vec?  ──Yes──▶  return false (double-vote)
    │ No
    ▼
Append reporter to Confirmations, persist
    │
    ▼
confirmations.len() >= threshold?  ──No──▶  return false
    │ Yes
    ▼
Set Merged(pr_id, repo_hash) = true
return true ✓
```

---

### Query Functions

#### `is_merged(pr_id: u64, repo_hash: BytesN<32>) → bool`
Returns `true` if the event has been finalized by enough reporters.

```rust
if client.is_merged(&123, &repo_hash) {
    // safe to award points
}
```

#### `get_confirmations(pr_id: u64, repo_hash: BytesN<32>) → u32`
Returns the current confirmation count for a pending event.

```rust
let count = client.get_confirmations(&123, &repo_hash);
// e.g. 1 — waiting on 1 more reporter (threshold = 2)
```

---

## Usage Examples

### 1. Initialize the contract

```rust
let env = Env::default();
let contract_id = env.register_contract(None, WaveOracle);
let client = WaveOracleClient::new(&env, &contract_id);

let admin = Address::generate(&env);

// Require 2 out of N reporters to confirm a merge
client.init(&admin, &2);
```

### 2. Register reporters

```rust
let reporter1 = Address::generate(&env); // GitHub App instance A
let reporter2 = Address::generate(&env); // GitHub App instance B

client.add_reporter(&reporter1);
client.add_reporter(&reporter2);
```

### 3. Reporters submit confirmations

```rust
let repo_hash = BytesN::from_array(&env, &[0xab; 32]); // SHA-256 of "org/repo"
let pr_id: u64 = 456;
let contributor = Symbol::new(&env, "alice");

// Reporter 1 observes the merge and submits
let done = client.verify_merge(&reporter1, &contributor, &pr_id, &repo_hash);
assert!(!done); // 1/2 — not finalized yet

// Reporter 2 independently confirms
let done = client.verify_merge(&reporter2, &contributor, &pr_id, &repo_hash);
assert!(done);  // 2/2 — finalized ✓
```

### 4. Downstream contract checks the oracle

```rust
// In your Wave Points contract:
pub fn claim_reward(env: Env, user: Address, pr_id: u64, repo_hash: BytesN<32>) {
    let oracle = WaveOracleClient::new(&env, &ORACLE_CONTRACT_ID);

    if !oracle.is_merged(&pr_id, &repo_hash) {
        panic!("PR not verified");
    }

    award_points(&env, &user, 100);
}
```

---

## Test Suite

### `src/test.rs`

```rust
#[test]
fn test_multi_sig_threshold() {
    // Two reporters must confirm before event is finalized
    client.init(&admin, &2);
    client.add_reporter(&r1);
    client.add_reporter(&r2);

    client.verify_merge(&r1, &user, &42, &repo_hash); // 1/2
    let result = client.verify_merge(&r2, &user, &42, &repo_hash); // 2/2
    assert!(result);
    assert!(client.is_merged(&42, &repo_hash));
}

#[test]
fn test_replay_prevention() {
    // Once finalized, re-submitting the same event is idempotent
    client.init(&admin, &1);
    client.add_reporter(&reporter);

    assert!(client.verify_merge(&reporter, &user, &7, &repo_hash));
    assert!(client.verify_merge(&reporter, &user, &7, &repo_hash)); // idempotent
    assert_eq!(client.get_confirmations(&7, &repo_hash), 1);        // still 1
}

#[test]
fn test_double_vote_ignored() {
    // Same reporter voting twice only counts once
    client.init(&admin, &3);
    client.add_reporter(&reporter);

    client.verify_merge(&reporter, &user, &99, &repo_hash);
    client.verify_merge(&reporter, &user, &99, &repo_hash);
    assert_eq!(client.get_confirmations(&99, &repo_hash), 1);
}

#[test]
#[should_panic(expected = "reporter not authorized")]
fn test_unauthorized_reporter() {
    client.init(&admin, &1);
    // stranger was never added via add_reporter
    client.verify_merge(&stranger, &user, &5, &repo_hash);
}
```

Run the tests:

```bash
cargo test
```

Expected output:

```
running 5 tests
test test::test_below_threshold         ... ok
test test::test_double_vote_ignored     ... ok
test test::test_multi_sig_threshold     ... ok
test test::test_replay_prevention       ... ok
test test::test_unauthorized_reporter   ... ok

test result: ok. 5 passed; 0 failed
```

---

## Security Properties

| Threat | Mitigation |
|--------|-----------|
| **Fake merge claim** | Only whitelisted reporters can submit; admin controls the whitelist |
| **Single compromised reporter** | Configurable M-of-N threshold — one bad actor cannot finalize alone |
| **Replay attack** | `(pr_id, repo_hash)` is a unique event nonce; finalized events are idempotent |
| **Double voting** | `Vec<Address>` deduplication — same reporter counted at most once per event |
| **Admin abuse** | Admin can only manage the reporter list, not directly finalize events |
| **Reverted PRs** | Reporters can withhold confirmation; admin can remove a misbehaving reporter |

---

## Building & Deploying

```bash
# Build WASM binary
cargo build --target wasm32-unknown-unknown --release

# Run tests
cargo test

# Deploy to Stellar testnet
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/wave_oracle.wasm \
  --network testnet \
  --source <YOUR_SECRET_KEY>

# Initialize (threshold = 2)
soroban contract invoke \
  --id <CONTRACT_ID> \
  --network testnet \
  --source <ADMIN_SECRET> \
  -- init \
  --admin <ADMIN_ADDRESS> \
  --threshold 2

# Add a reporter
soroban contract invoke \
  --id <CONTRACT_ID> \
  --network testnet \
  --source <ADMIN_SECRET> \
  -- add_reporter \
  --reporter <REPORTER_ADDRESS>
```

---

## License

MIT
