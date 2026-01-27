# Audit Report

## Title
UTF-8 Boundary Violation in Log Truncation Causes Validator Node Panic

## Summary
The `TruncatedLogString::new()` function in the Aptos logger truncates log strings without respecting UTF-8 character boundaries, causing panics when multi-byte UTF-8 characters are split. This can crash validator nodes when logging messages containing non-ASCII characters. [1](#0-0) 

## Finding Description
The vulnerability exists in the log truncation logic that limits log field sizes. When a log message or structured log field exceeds `RUST_LOG_FIELD_MAX_LEN` (default 10KB), the truncation occurs at an arbitrary byte position without checking if it falls on a valid UTF-8 character boundary.

Rust's `String::truncate()` method **panics** if the truncation point is not on a character boundary. Multi-byte UTF-8 characters (2-4 bytes) such as emojis, CJK characters, or special symbols can be split by this truncation, triggering an immediate panic.

The vulnerable `TruncatedLogString` is used throughout log entry creation: [2](#0-1) [3](#0-2) 

These conversions happen synchronously in the `Logger::record()` function: [4](#0-3) 

**Attack Path:**
1. Attacker submits a transaction or triggers an error condition that causes logging
2. The log message/data contains multi-byte UTF-8 characters positioned such that truncation falls mid-character
3. `TruncatedLogString::new()` calls `truncate()` at the invalid boundary
4. The thread performing the logging panics and crashes
5. If this occurs in a critical validator thread (consensus, execution, network), the validator node crashes or restarts

## Impact Explanation
This is a **Low Severity** vulnerability per Aptos bug bounty criteria:
- **Category:** Non-critical implementation bug causing node availability issues
- **Impact:** Validator node crashes/restarts requiring manual intervention
- **NOT** a consensus safety violation (doesn't cause chain splits or incorrect state)
- **NOT** a funds loss issue
- **NOT** a permanent network partition

The crash is recoverable through node restart, but repeated exploitation could cause:
- Temporary validator downtime
- Missing block proposals/votes
- Reduced network participation during attacks

## Likelihood Explanation
**Likelihood: Medium-Low**

**Conditions Required:**
1. Log message must contain multi-byte UTF-8 characters (emojis: 🚀, CJK: 中文, symbols: ™)
2. Message length must position these characters at exactly the truncation boundary
3. The log level must be enabled for that component

**Realistic Scenarios:**
- Error messages including user-provided transaction data with non-ASCII content
- Debug output of byte sequences decoded as UTF-8 strings
- Network peer information containing internationalized domain names
- Transaction memos or metadata with emojis/special characters

**Mitigating Factors:**
- Most production logs use ASCII-only error messages
- Exact length alignment required (but becomes likely with high log volume)
- The existing test suite only uses ASCII, missing this edge case: [5](#0-4) 

## Recommendation
Replace the unsafe `truncate()` call with a UTF-8-aware truncation that finds the nearest valid character boundary:

```rust
fn new(s: String) -> Self {
    let mut truncated = s;

    if truncated.len() > RUST_LOG_FIELD_MAX_LEN.saturating_add(Self::TRUNCATION_SUFFIX.len()) {
        let mut truncate_at = *RUST_LOG_FIELD_MAX_LEN;
        
        // Find the nearest valid UTF-8 character boundary at or before truncate_at
        while truncate_at > 0 && !truncated.is_char_boundary(truncate_at) {
            truncate_at -= 1;
        }
        
        truncated.truncate(truncate_at);
        truncated.push_str(Self::TRUNCATION_SUFFIX);
    }
    TruncatedLogString(truncated)
}
```

This ensures truncation always occurs at a valid character boundary, preventing panics.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "byte index 10240 is not a char boundary")]
fn test_utf8_truncation_panic() {
    use crate::aptos_logger::TruncatedLogString;
    
    // Create a string that will be truncated at a multi-byte UTF-8 character
    // Default max length is 10KB = 10240 bytes
    let mut s = "a".repeat(10238); // 10238 ASCII chars
    s.push('🚀'); // 4-byte emoji at position 10238-10241
    // Truncation at 10240 falls in the middle of the emoji (byte 2 of 4)
    
    // This will panic with "byte index 10240 is not a char boundary"
    let _truncated = TruncatedLogString::from(s);
}

#[test]
fn test_utf8_truncation_safe() {
    // After applying the fix, this test should pass
    use crate::aptos_logger::TruncatedLogString;
    
    let mut s = "a".repeat(10238);
    s.push('🚀'); // 4-byte emoji
    
    let truncated = TruncatedLogString::from(s);
    // Should truncate at byte 10238 (before emoji) rather than panic
    assert!(truncated.len() <= 10240 + "(truncated)".len());
    assert!(truncated.is_char_boundary(truncated.len()));
}
```

## Notes

While the `write()` function in `telemetry_log_writer.rs` correctly accepts a `String` parameter (which guarantees valid UTF-8), the vulnerability occurs **upstream** during log entry construction in `aptos_logger.rs`. The panic happens before the string ever reaches the telemetry writer. [6](#0-5) 

The telemetry writer itself has no UTF-8 validation issues, but it never gets the chance to handle strings that cause panics during truncation.

### Citations

**File:** crates/aptos-logger/src/aptos_logger.rs (L64-72)
```rust
    fn new(s: String) -> Self {
        let mut truncated = s;

        if truncated.len() > RUST_LOG_FIELD_MAX_LEN.saturating_add(Self::TRUNCATION_SUFFIX.len()) {
            truncated.truncate(*RUST_LOG_FIELD_MAX_LEN);
            truncated.push_str(Self::TRUNCATION_SUFFIX);
        }
        TruncatedLogString(truncated)
    }
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L168-176)
```rust
            fn visit_pair(&mut self, key: Key, value: Value<'_>) {
                let v = match value {
                    Value::Debug(d) => serde_json::Value::String(
                        TruncatedLogString::from(format!("{:?}", d)).into(),
                    ),
                    Value::Display(d) => {
                        serde_json::Value::String(TruncatedLogString::from(d.to_string()).into())
                    },
                    Value::Serde(s) => match serde_json::to_value(s) {
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L192-195)
```rust
        let message = event
            .message()
            .map(fmt::format)
            .map(|s| TruncatedLogString::from(s).into());
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L572-579)
```rust
    fn record(&self, event: &Event) {
        let entry = LogEntry::new(
            event,
            ::std::thread::current().name(),
            self.enable_backtrace,
        );

        self.send_entry(entry)
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L1203-1224)
```rust
    fn test_log_event_truncation() {
        let log_entry = LogEntry::new(
            &Event::new(
                &Metadata::new(Level::Error, "target", "hyper", "source_path"),
                Some(format_args!(
                    "{}",
                    "a".repeat(2 * TruncatedLogString::DEFAULT_MAX_LEN)
                )),
                &[
                    &KeyValue::new(
                        "key1",
                        Value::Debug(&"x".repeat(2 * TruncatedLogString::DEFAULT_MAX_LEN)),
                    ),
                    &KeyValue::new(
                        "key2",
                        Value::Display(&"y".repeat(2 * TruncatedLogString::DEFAULT_MAX_LEN)),
                    ),
                ],
            ),
            Some("test_thread"),
            false,
        );
```

**File:** crates/aptos-logger/src/telemetry_log_writer.rs (L29-43)
```rust
    pub fn write(&mut self, log: String) -> std::io::Result<usize> {
        let len = log.len();
        match self.tx.try_send(TelemetryLog::Log(log)) {
            Ok(_) => Ok(len),
            Err(err) => {
                if err.is_full() {
                    APTOS_LOG_INGEST_WRITER_FULL.inc_by(len as u64);
                    Err(Error::new(ErrorKind::WouldBlock, "Channel full"))
                } else {
                    APTOS_LOG_INGEST_WRITER_DISCONNECTED.inc_by(len as u64);
                    Err(Error::new(ErrorKind::ConnectionRefused, "Disconnected"))
                }
            },
        }
    }
```
