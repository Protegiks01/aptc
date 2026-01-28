> Searching codebase... [1](#0-0) [2](#0-1)

### Citations

**File:** crates/aptos-logger/src/aptos_logger.rs (L737-740)
```rust
    fn write(&self, log: String) {
        if let Err(err) = writeln!(self.log_file.write(), "{}", log) {
            eprintln!("Unable to write to log file: {}", err);
        }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L483-501)
```rust
fn run_and_log<F, L, R>(callback: F, log_cb: L, log_entry: LogEntry) -> Result<R, Error>
where
    F: FnOnce() -> Result<R, Error>,
    L: for<'a> Fn(SafetyLogSchema<'a>) -> SafetyLogSchema<'a>,
{
    let _timer = counters::start_timer("internal", log_entry.as_str());
    trace!(log_cb(SafetyLogSchema::new(log_entry, LogEvent::Request)));
    counters::increment_query(log_entry.as_str(), "request");
    callback()
        .inspect(|_v| {
            trace!(log_cb(SafetyLogSchema::new(log_entry, LogEvent::Success)));
            counters::increment_query(log_entry.as_str(), "success");
        })
        .inspect_err(|err| {
            warn!(log_cb(SafetyLogSchema::new(log_entry, LogEvent::Error)).error(err));
            counters::increment_query(log_entry.as_str(), "error");
        })
}

```
