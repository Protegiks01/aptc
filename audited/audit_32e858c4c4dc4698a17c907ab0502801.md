# Audit Report

## Title
Stack Overflow Risk in Symbol Pool Entry Recursive Deallocation

## Summary
The Move symbol pool's `Entry` struct uses recursive `Box<Entry>` chains without custom Drop handling, creating a stack overflow vulnerability when long hash collision chains are deallocated during pool cleanup or process termination.

## Finding Description

The symbol pool implementation uses an intrusive linked list structure where each `Entry` contains a `next: Bucket` field, defined as `Option<Box<Entry>>`. [1](#0-0) 

When a `Pool` is dropped (either at process termination or through explicit replacement as shown in test code), Rust's default drop behavior recursively deallocates the chain: [2](#0-1) 

The deallocation proceeds as follows:
1. `Box<[Bucket; NB_BUCKETS]>` is dropped, dropping all 4096 buckets
2. Each `Bucket` (an `Option<Box<Entry>>`) is dropped
3. For buckets with entries, `Box<Entry>` is dropped
4. This drops the `Entry`, which drops its `next` field
5. If `next` contains another `Box<Entry>`, steps 3-5 repeat recursively

Each recursion level consumes stack space (~16-64 bytes per frame). With chains containing tens of thousands of entries (achievable through hash collisions), this recursive deallocation can exceed available stack space and cause panic.

**Critical Evidence:** The Aptos team has already addressed this exact vulnerability pattern in the Sparse Merkle Tree implementation with an explicit mitigation: [3](#0-2) 

The comment explicitly states: "The descendant will be dropped after we free the Arc, which results in a chain of such structures being dropped recursively and that might trigger a stack overflow. To prevent that we follow the chain further to disconnect things beforehand."

This mitigation uses both a custom `Drop` implementation and an `AsyncConcurrentDropper`: [4](#0-3) 

**The symbol pool lacks both protections** - there is no custom Drop implementation for Entry, Pool, or Bucket, and no length limits on hash collision chains: [5](#0-4) 

## Impact Explanation

This constitutes a **Medium** severity vulnerability per the Aptos bug bounty criteria:

1. **Denial of Service**: Validator nodes, compilers, or Move parsers can crash during shutdown or pool cleanup when processing maliciously crafted input
2. **Infrastructure Disruption**: During coordinated upgrades or restarts, affected nodes would panic, potentially disrupting network operations
3. **State Inconsistency Risk**: While the crash occurs during cleanup, an unclean shutdown could leave intermediate state requiring manual intervention

The issue breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - stack space is a critical computational resource that should be bounded.

The impact is limited compared to Critical/High severity because:
- Runtime operations are unaffected (only cleanup/shutdown)
- Does not directly cause consensus failure or fund loss
- Requires specific triggering conditions

However, the fact that Aptos developers implemented explicit mitigation for this exact pattern in production code (Sparse Merkle Tree) demonstrates they consider it serious enough to warrant fixing.

## Likelihood Explanation

**Likelihood: Medium**

**Attack Requirements:**
1. Submit Move modules with many identifiers designed to create hash collisions
2. Build chains long enough to overflow stack (estimated 50,000-250,000 entries)
3. Trigger pool deallocation (shutdown, restart, or hypothetical pool replacement)

**Challenges:**
- The pool uses `DefaultHasher` (SipHash 1-3), which is resistant to collision attacks
- Creating intentional collisions requires significant computational effort
- The 4096-bucket structure provides some natural distribution

**Feasibility:**
- Birthday paradox attacks can find collisions probabilistically
- An attacker can submit modules incrementally over time
- No chain length limits prevent accumulation
- Process termination is inevitable and predictable

The combination of difficulty (hash collisions) and feasibility (eventual triggering) results in Medium likelihood.

## Recommendation

Implement the same mitigation strategy used in the Sparse Merkle Tree:

**Solution 1: Custom Drop Implementation**
Add a custom `Drop` for `Entry` or `Pool` that iteratively disconnects chain nodes instead of relying on recursive drop:

```rust
impl Drop for Pool {
    fn drop(&mut self) {
        for bucket in self.0.iter_mut() {
            // Iteratively unlink chains to prevent stack overflow
            let mut current = bucket.take();
            while let Some(mut entry) = current {
                current = entry.next.take();
                // entry is dropped here without recursion
            }
        }
    }
}
```

**Solution 2: Use AsyncConcurrentDropper**
Schedule deep chains for asynchronous dropping in a thread pool with larger stack:

```rust
use aptos_drop_helper::async_concurrent_dropper::AsyncConcurrentDropper;

static SYMBOL_POOL_DROPPER: Lazy<AsyncConcurrentDropper> =
    Lazy::new(|| AsyncConcurrentDropper::new("symbol_pool", 32, 8));

impl Drop for Pool {
    fn drop(&mut self) {
        for bucket in self.0.iter_mut() {
            if let Some(entry) = bucket.take() {
                SYMBOL_POOL_DROPPER.schedule_drop(entry);
            }
        }
    }
}
```

**Solution 3: Chain Length Limits**
Add a maximum chain length per bucket and either reject new insertions or rehash when exceeded.

## Proof of Concept

```rust
#[test]
fn test_deep_chain_stack_overflow() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Find strings that hash to the same bucket
    fn hash_to_bucket(s: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        let hash = hasher.finish();
        (hash & 0xFFF) as usize // BUCKET_MASK = 4095
    }
    
    let mut pool = Pool::new();
    let target_bucket = hash_to_bucket("test");
    
    // Create many collisions (this is simplified - real attack would
    // need to find actual collisions with DefaultHasher's random seed)
    let mut collision_count = 0;
    for i in 0..100_000 {
        let candidate = format!("identifier_{}", i);
        if hash_to_bucket(&candidate) == target_bucket {
            pool.insert(Cow::Owned(candidate));
            collision_count += 1;
            if collision_count > 10_000 {
                break; // Enough to potentially overflow
            }
        }
    }
    
    // Drop the pool - if chain is long enough, this will stack overflow
    drop(pool);
}
```

## Notes

The vulnerability exists at the intersection of:
1. **Design Choice**: Using intrusive linked lists for memory stability
2. **Implementation Gap**: Missing the same protections applied elsewhere in the codebase
3. **Rust Semantics**: Default recursive drop behavior for `Box<T>`

While the attack requires sophisticated preparation (hash collisions) and specific timing (shutdown/cleanup), the existence of identical mitigation in the Sparse Merkle Tree proves the Aptos team recognizes this as a legitimate concern warranting production fixes. The symbol pool should receive equivalent protection.

### Citations

**File:** third_party/move/move-symbol-pool/src/pool.rs (L49-56)
```rust
type Bucket = Option<Box<Entry>>;

/// A string in the pool.
pub(crate) struct Entry {
    pub(crate) string: Box<str>,
    hash: u64,
    next: Bucket,
}
```

**File:** third_party/move/move-symbol-pool/src/pool.rs (L83-117)
```rust
    pub(crate) fn insert(&mut self, string: Cow<str>) -> NonNull<Entry> {
        let hash = Self::hash(&string);
        // Access the top-level bucket in the pool's contiguous array that
        // contains the linked list of entries that contain the string.
        let bucket_index = (hash & BUCKET_MASK) as usize;
        let mut ptr: Option<&mut Box<Entry>> = self.0[bucket_index].as_mut();

        // Iterate over the entires in the bucket.
        while let Some(entry) = ptr.take() {
            // If we find the string we're looking for, don't add anything to
            // the pool. Instead, just return the existing entry.
            // NOTE: Strings with different hash values can't possibly be equal,
            // so comparing those hash values first ought to filter out unequal
            // strings faster than comparing the strings themselves.
            if entry.hash == hash && *entry.string == *string {
                return NonNull::from(&mut **entry);
            }
            ptr = entry.next.as_mut();
        }

        // The string doesn't exist in the pool yet; insert it at the head of
        // the linked list of entries.
        let mut entry = Box::new(Entry {
            string: string.into_owned().into_boxed_str(),
            hash,
            next: self.0[bucket_index].take(),
        });
        let ptr = NonNull::from(&mut *entry);

        // The bucket in the top-level contiguous array now points to the new
        // head of the linked list.
        self.0[bucket_index] = Some(entry);

        ptr
    }
```

**File:** third_party/move/move-symbol-pool/src/lib.rs (L50-51)
```rust
        // to by the Symbol is now no longer valid.
        let _ = replace(&mut SYMBOL_POOL.lock().unwrap().0, Pool::new().0);
```

**File:** storage/scratchpad/src/sparse_merkle/mod.rs (L117-134)
```rust
impl Drop for Inner {
    fn drop(&mut self) {
        // Drop the root in a different thread, because that's the slowest part.
        SUBTREE_DROPPER.schedule_drop(self.root.take());

        let mut stack = self.drain_children_for_drop();
        while let Some(descendant) = stack.pop() {
            if Arc::strong_count(&descendant) == 1 {
                // The only ref is the one we are now holding, so the
                // descendant will be dropped after we free the `Arc`, which results in a chain
                // of such structures being dropped recursively and that might trigger a stack
                // overflow. To prevent that we follow the chain further to disconnect things
                // beforehand.
                stack.extend(descendant.drain_children_for_drop());
            }
        }
        self.log_generation("drop");
    }
```

**File:** storage/scratchpad/src/sparse_merkle/dropper.rs (L9-10)
```rust
pub static SUBTREE_DROPPER: Lazy<AsyncConcurrentDropper> =
    Lazy::new(|| AsyncConcurrentDropper::new("smt_subtree", 32, 8));
```
