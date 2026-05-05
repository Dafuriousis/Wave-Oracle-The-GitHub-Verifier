#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Symbol, Vec};

mod test;

// ── Storage Keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Threshold,
    Reporter(Address),
    /// All reporters who confirmed a given (pr_id, repo_hash) event
    Confirmations(u64, BytesN<32>),
    /// Finalization flag — set once threshold is reached
    Merged(u64, BytesN<32>),
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct WaveOracle;

#[contractimpl]
impl WaveOracle {
    // ── Admin ─────────────────────────────────────────────────────────────────

    /// One-time initializer. Panics if called again.
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

    // ── Core ──────────────────────────────────────────────────────────────────

    /// Whitelisted reporter submits a merge confirmation.
    /// Returns `true` when the confirmation threshold is reached for the first time.
    pub fn verify_merge(
        env: Env,
        reporter: Address,
        _github_user: Symbol,
        pr_id: u64,
        repo_hash: BytesN<32>,
    ) -> bool {
        reporter.require_auth();

        // Whitelist check
        if !env
            .storage()
            .persistent()
            .get::<_, bool>(&DataKey::Reporter(reporter.clone()))
            .unwrap_or(false)
        {
            panic!("reporter not authorized");
        }

        // Already finalized — idempotent
        let merged_key = DataKey::Merged(pr_id, repo_hash.clone());
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&merged_key)
            .unwrap_or(false)
        {
            return true;
        }

        // Record confirmation, deduplicate double-votes
        let conf_key = DataKey::Confirmations(pr_id, repo_hash.clone());
        let mut confirmations: Vec<Address> = env
            .storage()
            .persistent()
            .get(&conf_key)
            .unwrap_or_else(|| Vec::new(&env));

        if confirmations.contains(&reporter) {
            return false;
        }
        confirmations.push_back(reporter);
        env.storage().persistent().set(&conf_key, &confirmations);

        // Finalize if threshold reached
        let threshold: u32 = env.storage().instance().get(&DataKey::Threshold).unwrap();
        if confirmations.len() >= threshold {
            env.storage().persistent().set(&merged_key, &true);
            return true;
        }

        false
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    pub fn is_merged(env: Env, pr_id: u64, repo_hash: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get::<_, bool>(&DataKey::Merged(pr_id, repo_hash))
            .unwrap_or(false)
    }

    pub fn get_confirmations(env: Env, pr_id: u64, repo_hash: BytesN<32>) -> u32 {
        let confirmations: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Confirmations(pr_id, repo_hash))
            .unwrap_or_else(|| Vec::new(&env));
        confirmations.len()
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
    }
}
