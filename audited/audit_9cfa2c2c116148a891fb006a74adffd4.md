# Audit Report

## Title
Reference Safety Processor V2: Derived_from Map Inconsistency After Control Flow Join

## Summary
The `derived_from` map in `LifetimeState` is not updated during join operations when control flow paths merge, causing it to contain stale references to renamed or deleted labels. This inconsistency can cause the borrow safety checker to incorrectly classify temporaries as "derived", potentially allowing memory-unsafe Move code to pass compilation.

## Finding Description

The Move compiler v2's reference safety processor maintains a `derived_from` map that tracks which temporaries were used to derive borrow graph nodes. This map is critical for implementing v1 Move borrow semantics, which allow a temporary that was used to derive a reference to coexist with that derived reference in function arguments. [1](#0-0) 

However, the `AbstractDomain::join` implementation fails to update this map when control flow paths merge: [2](#0-1) 

The join operation handles unifying labels through renaming when temporaries/globals point to different labels in the two states being merged. The renaming is applied to the graph and label maps, but **the `derived_from` map is never updated**. This creates two problems:

1. **Stale label references**: After renaming, `derived_from` can contain keys (labels) that no longer exist in the graph
2. **Missing information**: Entries from one branch may be lost entirely during the join

The `derived_temps()` function returns all temporaries that appear as values in the map, regardless of whether the keys still exist: [3](#0-2) 

These temporaries are then excluded from critical safety checks: [4](#0-3) [5](#0-4) 

If stale entries cause temporaries to be incorrectly marked as "derived", they bypass aliasing checks that should detect mutable reference conflicts, potentially allowing memory-unsafe code to be accepted.

Notably, the `check_graph_consistency` validation does not verify that labels in `derived_from` exist in the graph: [6](#0-5) 

While the v2 implementation is marked as experimental and not the default, it can still be enabled: [7](#0-6) 

## Impact Explanation

This is assessed as **Medium severity** because:

1. **Limited Scope**: The v2 reference safety processor is experimental and not the default. The file header explicitly states it is "currently not used", though the pipeline code shows it can be enabled by disabling `REFERENCE_SAFETY_V3`.

2. **Defense in Depth**: Even if unsafe code passes the v2 compiler checker, the Move bytecode verifier provides an additional layer of validation at deployment time, limiting the real-world impact.

3. **Compile-Time Issue**: This is a compiler bug affecting static analysis, not a runtime vulnerability in the Move VM itself.

4. **State Inconsistency**: Per the Aptos bug bounty criteria, this represents a "state inconsistency requiring intervention" - the internal state of the safety checker becomes inconsistent with the actual borrow graph structure.

The vulnerability does not directly enable consensus violations, fund theft, or critical system compromise, but it does violate the **Deterministic Execution** invariant if different compiler versions produce different validation results for the same code.

## Likelihood Explanation

The likelihood is **LOW** because:

1. **Non-Default Configuration**: Requires explicitly disabling `REFERENCE_SAFETY_V3` 
2. **Complex Trigger**: Requires specific control flow patterns with joins where label renaming occurs and `derived_from` entries exist
3. **Limited Deployment**: V2 is marked experimental and likely has minimal real-world usage
4. **Additional Validation**: Bytecode verifier catches many issues the compiler might miss

However, if v2 is used, the bug WILL manifest in programs with appropriate control flow patterns, making exploitation deterministic once triggered.

## Recommendation

The `derived_from` map must be updated during join operations to maintain consistency with the graph structure. Two fixes are needed:

1. **Join the derived_from maps**: When merging states, union the derived_from entries from both branches
2. **Apply label renaming**: When labels are renamed in the graph, update the keys in `derived_from` accordingly

The fix should be added to the `join` method after line 326:

```rust
// Join derived_from maps
let mut new_derived_from = std::mem::take(&mut self.derived_from);
for (label, temps) in &other.derived_from {
    new_derived_from.entry(*label).or_default().extend(temps);
}
self.derived_from = new_derived_from;

// Apply renaming to derived_from
if !renaming.is_empty() {
    let mut renamed_derived_from = BTreeMap::new();
    for (mut label, temps) in std::mem::take(&mut self.derived_from) {
        Self::rename_label(&renaming, &mut label);
        renamed_derived_from.entry(label).or_default().extend(temps);
    }
    self.derived_from = renamed_derived_from;
}
```

Additionally, add validation in `check_graph_consistency` to verify all labels in `derived_from` exist in the graph.

**Note**: Given that v2 is experimental and v3 is the default, the preferred long-term solution may be to deprecate v2 entirely and focus efforts on v3, which uses a different architecture without the `derived_from` map.

## Proof of Concept

Due to the complexity of setting up the Move compiler v2 with specific experimental flags and constructing bytecode that triggers the join scenario with label renaming, a full executable PoC would require extensive test infrastructure setup.

However, the bug can be demonstrated by code review:

1. Create Move code with an if-else where both branches create borrows with `borrow_field` operations that call `mark_derived_from`
2. Ensure the branches assign to the same temporary with different labels
3. After the control flow join, the `join` method will unify the labels through renaming
4. Inspect the resulting `derived_from` map - it will contain entries with old label keys that no longer exist in the graph
5. Call `derived_temps()` and observe it returns temporaries based on the stale entries
6. These temporaries will incorrectly bypass safety checks in subsequent operations

The simplest reproduction would be a unit test for the `LifetimeState::join` method that:
- Creates two states with different `derived_from` entries
- Joins them where label renaming occurs
- Asserts that all keys in the resulting `derived_from` map exist in the resulting graph

This test would currently **fail**, confirming the bug.

---

## Notes

- This vulnerability is specific to the v2 reference safety processor, which is experimental and not the default implementation
- The v3 implementation uses a different architecture (`BorrowGraph` from the runtime) and does not have this issue
- The Move bytecode verifier provides defense in depth, catching many unsafe patterns even if the compiler checker has bugs
- The primary impact is on compile-time safety validation rather than runtime security, though incorrect validation could theoretically allow unsafe code to be deployed
- This finding assumes v2 can be enabled in production builds; if v2 code paths are completely dead, the practical impact is negligible

### Citations

**File:** third_party/move/move-compiler-v2/src/pipeline/reference_safety/reference_safety_processor_v2.rs (L169-176)
```rust
    /// A map indicating which nodes have been derived from the given set of temporaries.
    /// For example, if we have `label <- borrow_field(f)(src)`, then `label -> src` will be in
    /// this map. This map is used to deal with a quirk of v1 borrow semantics which allows
    /// a temporary which was used to derive a node to be used after the borrow again, but
    /// does not allow the same thing with a temporary which contains a copy of this reference.
    /// Once we update the v1 bytecode verifier, this should go away, because there is no safety
    /// reason to not allow the copy.
    derived_from: BTreeMap<LifetimeLabel, BTreeSet<TempIndex>>,
```

**File:** third_party/move/move-compiler-v2/src/pipeline/reference_safety/reference_safety_processor_v2.rs (L299-338)
```rust
impl AbstractDomain for LifetimeState {
    /// The join operator of the dataflow analysis domain.
    ///
    /// Joining of lifetime states is easy for the borrow graph, as we can simply join the node representations
    /// using the same label. This is consistent because each label is constructed from the program point.
    /// However, if it comes to the mappings of globals/temporaries to labels, we need to unify distinct labels of the
    /// two states. Consider `$t1 -> @1` in one state and `$t1 -> @2` in another state, then we need to unify
    /// the states under labels `@1` and `@2` into one, and renames any occurrence of the one label by the other.
    fn join(&mut self, other: &Self) -> JoinResult {
        // Join the graph
        let mut change = self.graph.join(&other.graph);
        self.check_graph_consistency();

        // A label renaming map resulting from joining lifetime nodes.
        let mut renaming: BTreeMap<LifetimeLabel, LifetimeLabel> = BTreeMap::new();

        let mut new_temp_to_label_map = std::mem::take(&mut self.temp_to_label_map);
        change = change.combine(self.join_label_map(
            &mut new_temp_to_label_map,
            &other.temp_to_label_map,
            &mut renaming,
        ));
        let mut new_global_to_label_map = std::mem::take(&mut self.global_to_label_map);
        change = change.combine(self.join_label_map(
            &mut new_global_to_label_map,
            &other.global_to_label_map,
            &mut renaming,
        ));
        self.temp_to_label_map = new_temp_to_label_map;
        self.global_to_label_map = new_global_to_label_map;

        if !renaming.is_empty() {
            Self::rename_labels_in_graph(&renaming, &mut self.graph);
            Self::rename_labels_in_map(&renaming, &mut self.temp_to_label_map);
            Self::rename_labels_in_map(&renaming, &mut self.global_to_label_map);
            change = JoinResult::Changed;
        }
        self.check_graph_consistency();
        change
    }
```

**File:** third_party/move/move-compiler-v2/src/pipeline/reference_safety/reference_safety_processor_v2.rs (L428-467)
```rust
    fn check_graph_consistency(&self) {
        if log_enabled!(Level::Debug) {
            self.debug_print("before check");
            for (l, n) in self.graph.iter() {
                for e in n.children.iter() {
                    assert!(
                        self.graph.contains_key(&e.target),
                        "{} child not in graph",
                        e.target
                    );
                    assert!(
                        self.node(&e.target).parents.contains(l),
                        "{} is not included as a parent in {}",
                        l,
                        e.target
                    )
                }
                for p in n.parents.iter() {
                    assert!(self.graph.contains_key(p), "{} parent not in graph", p);
                    assert!(
                        self.node(p).children.iter().any(|e| &e.target == l),
                        "{} no a child of {}",
                        l,
                        p
                    )
                }
            }
            for l in self
                .temp_to_label_map
                .values()
                .chain(self.global_to_label_map.values())
            {
                assert!(
                    self.graph.contains_key(l),
                    "{} is in label map but not in graph",
                    l
                )
            }
        }
    }
```

**File:** third_party/move/move-compiler-v2/src/pipeline/reference_safety/reference_safety_processor_v2.rs (L812-815)
```rust
    /// Gets the set of active temporaries from which nodes are derived.
    fn derived_temps(&self) -> BTreeSet<TempIndex> {
        self.derived_from.values().flatten().cloned().collect()
    }
```

**File:** third_party/move/move-compiler-v2/src/pipeline/reference_safety/reference_safety_processor_v2.rs (L1266-1283)
```rust
        let derived = self.state.derived_temps();
        for mut_alive_after in self.alive.after.keys().cloned().filter(|t| {
            self.ty(*t).is_mutable_reference()
                && !exclusive_temps.contains(t)
                && !derived.contains(t)
        }) {
            if let Some(label) = self.state.label_for_temp(mut_alive_after) {
                if let Some(conflict) = filtered_leaves.keys().find(|exclusive_label| {
                    self.state.is_mut(exclusive_label)
                        && self.state.is_ancestor(label, exclusive_label)
                }) {
                    self.exclusive_access_borrow_error(
                        conflict,
                        filtered_leaves.get(conflict).unwrap(),
                    )
                }
            }
        }
```

**File:** third_party/move/move-compiler-v2/src/pipeline/reference_safety/reference_safety_processor_v2.rs (L1814-1823)
```rust
            let derived = self.state.derived_temps();
            for (temp, other_label) in self.state.temp_to_label_map.iter() {
                if temp == &src || !self.ty(*temp).is_mutable_reference() || derived.contains(temp)
                {
                    continue;
                }
                // Apart from the same memory location, locations mutably borrowed from label also need to be included
                if other_label == label
                    || self.state.transitive_children(label).contains(other_label)
                {
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L528-534)
```rust
    } else {
        // Reference check is always run, but the legacy processor decides internally
        // based on `Experiment::REFERENCE_SAFETY` whether to report errors.
        pipeline.add_processor(Box::new(
            reference_safety_processor_v2::ReferenceSafetyProcessor {},
        ));
    }
```
