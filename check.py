def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific Aptos Core file.

    Args:
        target_file: The specific file path to focus question generation on
                    (e.g., "consensus/src/round_manager.rs" or "aptos-move/aptos-vm/src/aptos_vm.rs")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""  
# **Generate 150+ Targeted Security Audit Questions for Aptos Core**  
  
## **Context**  
  
The target project is **Aptos Core**, a high-performance Layer 1 blockchain implementing the AptosBFT consensus protocol and Move smart contract language. Aptos provides parallel execution, sub-second finality, and high throughput while maintaining security guarantees through Byzantine Fault Tolerant consensus.  
  
Aptos uses the Move programming language for smart contracts, which provides resource-oriented programming and formal verification capabilities. The blockchain maintains state through AptosDB with Jellyfish Merkle Trees and implements a comprehensive governance system for on-chain protocol upgrades.  
  
## **Scope**  
  
**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`  
  
Note: The questions must be generated from **`{target_file}`** only. If you cannot generate enough questions from this single file, provide as many quality questions as you can extract from the file's logic and interactions. **DO NOT return empty results** - give whatever questions you can derive from the target file.  
  
If you cannot reach 150 questions from this file alone, generate as many high-quality questions as the file's complexity allows (minimum target: 50-100 questions for large critical files, 20-50 for smaller files).  
  
**Full Context - Critical Aptos Components (for reference only):**  
If a file is more than a thousand lines you can generate as many as 300+ questions as you can, but always generate as many as you can - don't give other responses.  
If there are cryptographic operations, math logic, or state transition functions, generate comprehensive questions covering all edge cases and attack vectors.  
  
### **Core Aptos Components**  
  
```python  
core_components = [  
    # Consensus Layer  
    "consensus/src/round_manager.rs",           # AptosBFT round management  
    "consensus/src/epoch_manager.rs",          # Epoch transition logic  
    "consensus/src/liveness/round_state.rs",   # Round state machine  
    "consensus/src/liveness/proposal_generator.rs", # Block proposal generation  
    "consensus/src/safety_rules.rs",           # Safety rule enforcement  
      
    # Execution Engine  
    "aptos-move/aptos-vm/src/aptos_vm.rs",     # AptosVM implementation  
    "aptos-move/aptos-vm/src/gas.rs",          # Gas metering  
    "aptos-move/aptos-vm/src/data_cache.rs",   # Data access layer  
    "aptos-move/aptos-vm/src/move_vm_ext/",    # MoveVM extensions  
      
    # Aptos Framework (Move)  
    "aptos-move/framework/aptos-framework/sources/aptos_governance.move", # Governance  
    "aptos-move/framework/aptos-framework/sources/stake.move",            # Staking  
    "aptos-move/framework/aptos-framework/sources/coin.move",             # Coin operations  
    "aptos-move/framework/aptos-framework/sources/transaction_validation.move", # TX validation  
    "aptos-move/framework/aptos-framework/sources/aptos_account.move",    # Account management  
      
    # Storage System  
    "storage/aptosdb/src/state_store/mod.rs",    # State store coordinator  
    "storage/aptosdb/src/state_merkle_db.rs",    # Jellyfish Merkle tree  
    "storage/aptosdb/src/state_kv_db.rs",        # Key-value storage  
    "storage/aptosdb/src/ledger_db/mod.rs",      # Transaction storage  
      
    # Network Layer  
    "network/src/network_interface.rs",          # P2P networking  
    "consensus/src/network.rs",                  # Consensus messaging  
    "mempool/src/mempool.rs",                    # Transaction pool  
      
    # API Layer  
    "api/src/transactions.rs",                   # Transaction API  
    "api/src/accounts.rs",                       # Account API  
    "api/src/state.rs",                          # State query API  
      
    # Types & Config  
    "types/src/validator_verifier.rs",           # Validator verification  
    "config/src/config/consensus_config.rs",     # Consensus configuration  
]
```
  
### **Aptos Architecture & Critical Security Layers**  
  
1. **Consensus Layer (AptosBFT)**  
   - **Validator Management**: Dynamic validator set through staking and governance  
   - **Block Proposal**: Rotating leader election with VRF-based randomness  
   - **Voting Rules**: 3-chain commit rule for safety guarantees  
   - **Epoch Management**: Periodic validator set updates and reconfiguration  
   - **Safety Rules**: Persistent safety data preventing double-signing  
   - **Byzantine Tolerance**: Secure with < 1/3 malicious validators  
  
2. **Execution Engine (AptosVM & Move)**  
   - **Transaction Execution**: Move bytecode execution with resource safety  
   - **Gas Metering**: Precise gas calculation preventing DoS  
   - **Parallel Execution**: Block-STM for concurrent transaction processing  
   - **State Commitment**: Jellyfish Merkle tree for state verification  
   - **Prologue/Epilogue**: Transaction validation and finalization  
   - **Resource Model**: Move's type-safe resource management  
  
3. **Storage System (AptosDB)**  
   - **State Storage**: Sharded key-value and Merkle tree storage  
   - **Pruning**: Configurable history pruning for storage efficiency  
   - **Snapshots**: State snapshots for fast synchronization  
   - **Buffered Writes**: Asynchronous commit pipeline  
   - **Merkle Proofs**: Cryptographic state verification  
  
4. **On-Chain Governance**  
   - **Proposal System**: Multi-step governance proposals  
   - **Voting Power**: Stake-based voting with delegation  
   - **Feature Flags**: Gradual feature rollout mechanism  
   - **Protocol Upgrades**: On-chain code deployment and upgrades  
   - **Treasury Management**: Community fund management  
  
5. **Staking System**  
   - **Validator Registration**: Stake requirements and performance bonds  
   - **Reward Distribution**: Inflation-based rewards and fees  
   - **Penalty System**: Slashing for misbehavior  
   - **Delegation**: Stake delegation to validators  
   - **Performance Tracking**: Validator performance monitoring  
  
### **Critical Security Invariants**  
  
**Consensus Security**  
- **Validator Authority**: Only authorized validators can propose blocks  
- **Block Signing**: Blocks must have valid quorum certificates  
- **Safety Guarantees**: No double-spending with < 1/3 Byzantine  
- **Liveness**: Network progresses with honest majority  
- **Epoch Transitions**: Safe validator set changes without forks  
  
**State Integrity**  
- **Deterministic Execution**: All validators produce identical state roots  
- **Resource Safety**: Move's resource model prevents double-spending  
- **Gas Consistency**: Gas calculations are deterministic across nodes  
- **Merkle Integrity**: State commitment matches actual state  
- **Atomic Transitions**: State changes are all-or-nothing  
  
**Transaction Security**  
- **Signature Validation**: All transactions require valid signatures  
- **Sequence Numbers**: Nonce-based replay protection  
- **Gas Limits**: Transactions cannot exceed gas limits  
- **Access Control**: System addresses are protected  
- **Type Safety**: Move's type system prevents invalid operations  
  
**Economic Security**  
- **Stake Requirements**: Economic barriers to validator entry  
- **Slashing Penalties**: Economic disincentives for misbehavior  
- **Reward Distribution**: Fair and predictable reward allocation  
- **Gas Economics**: Proper gas pricing for resource allocation  
- **Treasury Controls**: Community fund protection mechanisms  
  
### **In-Scope Vulnerability Categories (Aptos Bug Bounty)**  
  
**Critical Severity (up to $1,000,000)**  
- **Loss of Funds**: Direct theft or unlimited minting of APT/tokens  
- **Consensus/Safety Violations**: Double-spending, chain splits, safety breaks  
- **Network Partition**: Non-recoverable splits requiring hardfork  
- **Loss of Liveness**: Total network halt or unavailability  
- **Permanent Freezing**: Funds locked without recovery (requires hardfork)  
- **Remote Code Execution**: RCE on validator nodes  
- **Cryptographic Vulnerabilities**: Practical breaks in crypto primitives  
  
**High Severity (up to $50,000)**  
- **Validator Slowdowns**: Performance degradation affecting consensus  
- **API Crashes**: REST API failures affecting network participation  
- **Protocol Violations**: Significant consensus or implementation bugs  
  
**Medium Severity (up to $10,000)**  
- **Limited Funds Loss**: Small-scale theft or manipulation  
- **State Inconsistencies**: Recoverable state corruption issues  
  
**Out of Scope**  
- Network DoS attacks (explicitly excluded)  
- Social engineering vulnerabilities  
- Test/build infrastructure attacks  
- Performance optimizations without security impact  
  
### **Goals for Question Generation**  
  
- **Real Exploit Scenarios**: Each question describes a plausible attack by malicious validators, transaction senders, or network peers  
- **Concrete & Actionable**: Reference specific functions, structs, or logic flows in `{target_file}`  
- **High Impact**: Prioritize questions leading to Critical/High/Medium bounty impacts  
- **Deep Technical Detail**: Focus on subtle bugs: race conditions, consensus edge cases, state transitions, Move VM bugs  
- **Breadth Within Target File**: Cover all major functions and edge cases in `{target_file}`  
- **Respect Trust Model**: Assume validators may be Byzantine (< 1/3); focus on protocol security  
- **No Generic Questions**: Avoid "are there access control issues?" → Instead: "In `{target_file}: functionName()`, can attacker exploit X to cause Y?"  
  
### **Question Format Template**  
  
Each question MUST follow this Python list format:  
  
```python  
questions = [  
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact with severity category?",  
      
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",  
      
    # ... continue with all generated questions  
]  
```  
  
**Example Format** (if target_file is consensus/src/round_manager.rs):  
  
```python  
questions = [  
    "[File: consensus/src/round_manager.rs] [Function: process_proposal()] [Consensus bypass] Can an attacker craft a malicious proposal with manipulated round numbers that bypasses voting rules, allowing them to commit conflicting blocks and cause double-spending? (Critical)",  
      
    "[File: consensus/src/round_manager.rs] [Function: process_vote()] [Safety violation] Does vote validation properly check for equivocation, or can a validator sign conflicting votes for different blocks at the same round, breaking AptosBFT safety guarantees? (Critical)",  
      
    "[File: consensus/src/round_manager.rs] [Function: handle_timeout()] [Liveness attack] Can timeout certificates be forged or manipulated to force unnecessary round changes, potentially halting consensus progress and causing total loss of liveness? (High)",  
      
    "[File: consensus/src/round_manager.rs] [Function: new_round()] [State inconsistency] Are round state transitions atomic, or can race conditions during concurrent round changes lead to inconsistent state across validators causing network partition? (High)",  
]  
```  
  
### **Output Requirements**  
  
Generate security audit questions focusing EXCLUSIVELY on `{target_file}` that:  
  
- **Target ONLY `{target_file}`** - all questions must reference this file  
- **Reference specific functions, methods, structs, or logic sections** within `{target_file}`  
- **Describe concrete attack vectors** (not "could there be a bug?" but "can attacker do X by exploiting Y in `{target_file}`?")  
- **Tie to impact categories** (consensus failure, fund loss, liveness issues, validator manipulation, state corruption)  
- **Include severity classification** (Critical/High/Medium/Low) based on Aptos bounty impact  
- **Respect trust model** (assume < 1/3 Byzantine validators; focus on protocol security)  
- **Cover diverse attack surfaces** within `{target_file}`: validation logic, state transitions, error handling, edge cases, concurrent access, cryptographic operations, integer math  
- **Focus on high-severity bugs**: prioritize Critical > High > Medium > Low  
- **Avoid out-of-scope issues**: network DoS, social engineering, performance optimizations  
- **Use the exact Python list format** shown above  
- **Be detailed and technical**: assume auditor has deep blockchain/Move knowledge  
- **Consider Rust/Move-specific issues**: race conditions, unsafe blocks, integer overflow, borrow checker issues, resource safety violations  
  
### **Target Question Count**  
  
- **Large critical files** (>1000 lines like aptos_vm.rs, round_manager.rs): Aim for 150-300 questions  
- **Medium files** (500-1000 lines like epoch_manager.rs, governance.move): Aim for 80-150 questions  
- **Smaller files** (<500 lines like config.rs, account.move): Aim for 30-80 questions  
- **Provide as many quality questions as the file's complexity allows** - do NOT return empty results  
  
### **Special Considerations for Aptos Code**  
  
- **Rust concurrency**: Race conditions in async/await, Arc/Mutex usage, channel operations  
- **Move VM**: Bytecode interpretation bugs, gas metering errors, resource access violations  
- **Consensus timing**: Timeout handling, round synchronization, leader election  
- **State storage**: Merkle tree inconsistencies, sharding issues, snapshot corruption  
- **Cryptography**: BLS signature aggregation, VRF randomness, hash collisions  
- **Governance**: Voting power calculation, proposal execution, feature flag abuse  
- **Staking**: Reward calculation errors, validator set manipulation, performance tracking  
  
Begin generating questions for `{target_file}` now.  
"""
    return prompt
