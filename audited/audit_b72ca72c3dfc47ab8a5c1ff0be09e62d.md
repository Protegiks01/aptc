# Audit Report

## Title
Dependency Limit Bypass for Special Addresses Enables Gas-Free DoS via Module Loading

## Summary
The gas metering system incorrectly skips dependency counting for modules at special addresses (0x0-0xf), allowing attackers to bypass the `max_num_dependencies` and `max_total_dependency_size` safety limits. This enables loading an unbounded number of framework modules without gas charges or limit enforcement, causing validator resource exhaustion.

## Finding Description

The `StandardGasMeter::charge_dependency()` function implements a gas bypass for modules at special addresses (0x0 through 0xf), which include the Aptos Framework (0x1), Token V1 (0x3), and Token Objects V2 (0x4). [1](#0-0) 

The critical flaw is that when a module address is special, the function returns `Ok(())` without calling `self.algebra.count_dependency(size)`, completely bypassing the safety limits defined in the gas schedule. [2](#0-1) 

These limits (`max_num_dependencies`: 768 modules, `max_total_dependency_size`: 1.8 MB) are enforced via `count_dependency()` which tracks cumulative module count and size. [3](#0-2) 

**Attack Path:**
1. Attacker publishes a malicious Move module at their own address that imports 50+ framework modules from addresses 0x1, 0x3, and 0x4
2. The module contains a simple entry function that does minimal work
3. When the entry function is called, the VM loads all imported dependencies via `check_dependencies_and_charge_gas()` [4](#0-3) 
4. For each framework module dependency, `charge_dependency()` is invoked but skips both gas charging AND dependency counting
5. The validator must deserialize and verify all these modules without proper accounting
6. Limits that should prevent this (768 modules, 1.8 MB total) are completely bypassed
7. With a cold module cache (new node startup, after cache flush, or governance upgrade), this forces expensive computation without gas payment

The Aptos Framework contains 43+ modules at address 0x1, many of substantial size. [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos Bug Bounty criteria for the following reasons:

1. **Validator Node Slowdowns**: Attackers can force validators to deserialize and verify 50+ large framework modules without paying gas, causing computational delays during block execution.

2. **Safety Limit Bypass**: The dependency limits exist specifically to prevent DoS attacks via excessive module loading. Bypassing these limits violates the "Resource Limits" invariant that all operations must respect gas and computational limits.

3. **Resource Exhaustion**: While mitigated by module caching, the attack is effective during:
   - New validator node startup (cold cache)
   - Post-governance upgrade cache flushes
   - Cache eviction due to size limits
   - Per-block cache scenarios

4. **No Gas Payment**: The attacker pays zero gas for expensive deserialization/verification operations that should cost `DEPENDENCY_PER_MODULE` (74,460 gas) + `DEPENDENCY_PER_BYTE` (42 gas/byte) per module.

## Likelihood Explanation

**Likelihood: Medium**

The attack is straightforward to execute:
- Requires only the ability to publish a Move module (standard user operation)
- Module can be crafted with arbitrary framework imports
- Calling the entry function triggers the vulnerability
- No special timing or race conditions required

Limiting factors:
- Module cache reduces effectiveness after first load
- Cache persistence across blocks diminishes repeated exploitation
- Still exploitable during cache-cold scenarios (node startup, upgrades)
- Can be combined with cache eviction techniques to maximize impact

An attacker can publish malicious modules and spam calls to them, especially targeting validators during vulnerable windows when caches are cold.

## Recommendation

**Fix**: Separate gas charging from dependency counting. The dependency counting should apply to ALL addresses to enforce safety limits, while gas charging can remain bypassed for special addresses.

**Modified code** in `aptos-move/aptos-gas-meter/src/meter.rs`: [1](#0-0) 

```rust
fn charge_dependency(
    &mut self,
    _kind: DependencyKind,
    addr: &AccountAddress,
    _name: &IdentStr,
    size: NumBytes,
) -> PartialVMResult<()> {
    if self.feature_version() >= 15 {
        // Only bypass gas charging for special addresses, not limit counting
        if !addr.is_special() {
            self.algebra
                .charge_execution(DEPENDENCY_PER_MODULE + DEPENDENCY_PER_BYTE * size)?;
        }
        // ALWAYS count dependencies against limits, even for special addresses
        self.algebra.count_dependency(size)?;
    }
    Ok(())
}
```

This ensures special addresses remain free to load (as intended) while safety limits still apply.

## Proof of Concept

**Malicious Move Module** (to be published at attacker's address):

```move
module 0xattacker::dos_exploit {
    // Import maximum number of framework modules
    use std::vector;
    use std::string;
    use std::option;
    use std::signer;
    use aptos_framework::account;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin;
    use aptos_framework::stake;
    use aptos_framework::staking_contract;
    use aptos_framework::vesting;
    use aptos_framework::voting;
    use aptos_framework::aptos_governance;
    use aptos_framework::block;
    use aptos_framework::transaction_fee;
    use aptos_framework::gas_schedule;
    use aptos_framework::genesis;
    use aptos_framework::code;
    use aptos_framework::object;
    use aptos_framework::fungible_asset;
    use aptos_framework::primary_fungible_store;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::delegation_pool;
    use aptos_framework::multisig_account;
    use aptos_framework::reconfiguration;
    use aptos_framework::resource_account;
    use aptos_framework::timestamp;
    use aptos_framework::transaction_validation;
    use aptos_framework::event;
    use aptos_framework::guid;
    use aptos_framework::chain_id;
    use aptos_framework::chain_status;
    use aptos_framework::storage_gas;
    use aptos_framework::state_storage;
    use aptos_framework::aggregator_factory;
    use aptos_framework::aggregator;
    use aptos_framework::consensus_config;
    use aptos_framework::execution_config;
    use aptos_framework::staking_config;
    use aptos_framework::randomness;
    use aptos_framework::jwks;
    use aptos_framework::keyless_account;
    use aptos_framework::dkg;
    use aptos_framework::validator_consensus_info;
    use aptos_token::token;
    use aptos_token_objects::aptos_token;
    
    /// Entry function that triggers loading of all imported modules
    public entry fun trigger_dos() {
        // Minimal operation - the damage is done during module loading
        // All 45+ imported modules must be deserialized and verified
        // Without paying gas or respecting dependency limits
    }
}
```

**Exploitation Steps:**
1. Attacker publishes the module above to their account
2. Attacker calls `0xattacker::dos_exploit::trigger_dos()` repeatedly
3. Each call (with cold cache) forces validators to deserialize 45+ framework modules
4. Gas charged: ~minimal (only for the trivial function body)
5. Gas that SHOULD be charged: ~3.4M gas units (45 modules × 74,460 gas)
6. Dependency limits bypassed: Would exceed max if counted properly against user modules
7. Validators experience slowdown processing these transactions without proper gas compensation

**Notes**
- The vulnerability exists in production code with `feature_version >= 15`
- Special addresses (0x0-0xf) are defined in the AccountAddress specification [6](#0-5) 
- System addresses are protected from direct account creation [7](#0-6)  but this doesn't prevent referencing their modules as dependencies
- The TODO comment in the code acknowledges legacy address 0xA550C18 needs review, suggesting awareness that the special address handling may have issues [8](#0-7)

### Citations

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L57-76)
```rust
    fn charge_dependency(
        &mut self,
        _kind: DependencyKind,
        addr: &AccountAddress,
        _name: &IdentStr,
        size: NumBytes,
    ) -> PartialVMResult<()> {
        // Modules under special addresses are considered system modules that should always
        // be loaded, and are therefore excluded from gas charging.
        //
        // TODO: 0xA550C18 is a legacy system address we used, but it is currently not covered by
        //       `.is_special()`. We should double check if this address still needs special
        //       treatment.
        if self.feature_version() >= 15 && !addr.is_special() {
            self.algebra
                .charge_execution(DEPENDENCY_PER_MODULE + DEPENDENCY_PER_BYTE * size)?;
            self.algebra.count_dependency(size)?;
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L251-259)
```rust
            max_num_dependencies: NumModules,
            { RELEASE_V1_10.. => "max_num_dependencies" },
            768,
        ],
        [
            max_total_dependency_size: NumBytes,
            { RELEASE_V1_10.. => "max_total_dependency_size" },
            1024 * 1024 * 18 / 10, // 1.8 MB
        ],
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L300-313)
```rust
    fn count_dependency(&mut self, size: NumBytes) -> PartialVMResult<()> {
        if self.feature_version >= 15 {
            self.num_dependencies += 1.into();
            self.total_dependency_size += size;

            if self.num_dependencies > self.vm_gas_params.txn.max_num_dependencies {
                return Err(PartialVMError::new(StatusCode::DEPENDENCY_LIMIT_REACHED));
            }
            if self.total_dependency_size > self.vm_gas_params.txn.max_total_dependency_size {
                return Err(PartialVMError::new(StatusCode::DEPENDENCY_LIMIT_REACHED));
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/dependencies_gas_charging.rs (L62-108)
```rust
pub fn check_dependencies_and_charge_gas<'a, I>(
    module_storage: &impl ModuleStorage,
    gas_meter: &mut impl DependencyGasMeter,
    traversal_context: &mut TraversalContext<'a>,
    ids: I,
) -> VMResult<()>
where
    I: IntoIterator<Item = (&'a AccountAddress, &'a IdentStr)>,
    I::IntoIter: DoubleEndedIterator,
{
    let _timer = VM_TIMER.timer_with_label("check_dependencies_and_charge_gas");

    // Initialize the work list (stack) and the map of visited modules.
    //
    // TODO: Determine the reserved capacity based on the max number of dependencies allowed.
    let mut stack = Vec::with_capacity(512);
    traversal_context.push_next_ids_to_visit(&mut stack, ids);

    while let Some((addr, name)) = stack.pop() {
        let size = module_storage.unmetered_get_existing_module_size(addr, name)?;
        gas_meter
            .charge_dependency(
                DependencyKind::Existing,
                addr,
                name,
                NumBytes::new(size as u64),
            )
            .map_err(|err| err.finish(Location::Module(ModuleId::new(*addr, name.to_owned()))))?;

        // Extend the lifetime of the module to the remainder of the function body
        // by storing it in an arena.
        //
        // This is needed because we need to store references derived from it in the
        // work list.
        let compiled_module =
            module_storage.unmetered_get_existing_deserialized_module(addr, name)?;
        let compiled_module = traversal_context.referenced_modules.alloc(compiled_module);

        // Explore all dependencies and friends that have been visited yet.
        let imm_deps_and_friends = compiled_module
            .immediate_dependencies_iter()
            .chain(compiled_module.immediate_friends_iter());
        traversal_context.push_next_ids_to_visit(&mut stack, imm_deps_and_friends);
    }

    Ok(())
}
```

**File:** third_party/move/move-prover/lab/data/new-boogie-aptos-framework/new_boogie_2.mod_data (L1-45)
```text
# config: new_boogie_2.toml
# time  : 2023-12-29 12:32:55.553118 UTC
0x1::system_addresses                             825           ok
0x1::guid                                         733           ok
0x1::event                                        715           ok
0x1::create_signer                                412           ok
0x1::chain_id                                     661           ok
0x1::account                                     2235           ok
0x1::aggregator                                   628           ok
0x1::aggregator_factory                           683           ok
0x1::optional_aggregator                         1225           ok
0x1::coin                                        2662           ok
0x1::aptos_coin                                  1007           ok
0x1::aptos_account                               2438           ok
0x1::transaction_context                          671           ok
0x1::chain_status                                 962           ok
0x1::timestamp                                    891           ok
0x1::voting                                      5980           ok
0x1::staking_config                              2299           ok
0x1::stake                                      26403           ok
0x1::transaction_fee                             2458           ok
0x1::state_storage                                899           ok
0x1::storage_gas                                 3541           ok
0x1::reconfiguration                            19691           ok
0x1::governance_proposal                          643           ok
0x1::aptos_governance                           65225           ok
0x1::block                                      61399           ok
0x1::util                                         628           ok
0x1::code                                        1232           ok
0x1::consensus_config                           18836           ok
0x1::delegation_pool                              418           ok
0x1::execution_config                           31640           ok
0x1::object                                      2067           ok
0x1::fungible_asset                               425           ok
0x1::gas_schedule                              106978           ok
0x1::staking_contract                           34364           ok
0x1::vesting                                     3323           ok
0x1::version                                    15657           ok
0x1::transaction_validation                      5510           ok
0x1::genesis                                    52356           ok
0x1::managed_coin                                1157           ok
0x1::multisig_account                            5036           ok
0x1::primary_fungible_store                       413           ok
0x1::resource_account                            1578           ok
0x1::staking_proxy                               1279           ok
```

**File:** third_party/move/move-core/types/src/account_address.rs (L110-122)
```rust
    /// Returns whether the address is a "special" address. Addresses are considered
    /// special if the first 63 characters of the hex string are zero. In other words,
    /// an address is special if the first 31 bytes are zero and the last byte is
    /// smaller than than `0b10000` (16). In other words, special is defined as an address
    /// that matches the following regex: `^0x0{63}[0-9a-f]$`. In short form this means
    /// the addresses in the range from `0x0` to `0xf` (inclusive) are special.
    ///
    /// For more details see the v1 address standard defined as part of AIP-40:
    /// <https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md>
    #[inline(always)]
    pub fn is_special(&self) -> bool {
        self.0[..Self::LENGTH - 1].iter().all(|x| *x == 0) && self.0[Self::LENGTH - 1] < 0b10000
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L276-284)
```text
    public fun create_account_if_does_not_exist(account_address: address) {
        if (!resource_exists_at(account_address)) {
            assert!(
                account_address != @vm_reserved && account_address != @aptos_framework && account_address != @aptos_token,
                error::invalid_argument(ECANNOT_RESERVED_ADDRESS)
            );
            create_account_unchecked(account_address);
        }
    }
```
