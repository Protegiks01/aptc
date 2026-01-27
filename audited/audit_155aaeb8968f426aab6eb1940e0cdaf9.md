# Audit Report

## Title
Private Key Exposure Through Serde Serialization Bypass in Logging System

## Summary
The `SilentDebug` and `SilentDisplay` macros properly protect against Debug and Display formatting of private keys, but fail to prevent exposure through serde serialization in the logging system. When developers log structs containing private keys using default structured logging (without `?` or `%` sigils), the keys are serialized to JSON format and exposed as hex-encoded strings in log files.

## Finding Description

The `secp256r1_ecdsa::PrivateKey` type uses `SilentDebug` and `SilentDisplay` macros to prevent accidental key exposure. [1](#0-0) 

These macros correctly implement Debug and Display traits to output `<elided secret for PrivateKey>` instead of actual key material. [2](#0-1) 

However, the `SerializeKey` derive macro implements serde serialization that **exposes the private key** when using human-readable serializers. [3](#0-2) 

When serialized with a human-readable format, the implementation calls `to_encoded_string()`, which converts the private key to hex format. [4](#0-3) 

The Aptos logging system uses three value types: Debug (protected), Display (protected), and **Serde (NOT protected)**. [5](#0-4) 

The logging macros default to serde serialization when no sigil is used. [6](#0-5) 

**Attack Scenario:**
```rust
// Developer accidentally logs a config containing a private key
#[derive(Serialize)]
struct ValidatorConfig {
    consensus_key: bls12381::PrivateKey,
}

let config = load_config();
info!(config = config); // Private key exposed as hex in logs!
info!(config = ?config); // Safe - uses Debug (SilentDebug)
```

## Impact Explanation

**Severity: Low (Minor Information Leak)**

While this represents a design gap in the security model, the actual impact is limited:

1. Requires developer error (logging private keys with wrong syntax)
2. Requires attacker access to log files
3. No evidence found of actual exploitation in current codebase

However, if exploited, the consequences could be severe:
- Validator consensus key compromise
- Transaction signing key theft  
- Potential consensus manipulation

The cryptographic correctness invariant is violated when private keys are logged, breaking the fundamental security assumption that private keys remain confidential.

## Likelihood Explanation

**Likelihood: Low**

Exploitation requires:
1. A developer mistake (using `key = value` instead of `key = ?value`)
2. Logging of sensitive structs containing private keys
3. Attacker access to production log files
4. Logs not being sanitized or rotated securely

The current codebase shows no evidence of private keys being logged this way. The `IdentityBlob` type that contains private keys uses YAML serialization for file storage (intentional), not for logging. [7](#0-6) 

## Recommendation

Implement a custom `Serialize` implementation for private key types that always elides the content, similar to `SilentDebug`:

```rust
impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("<elided secret for PrivateKey>")
    }
}
```

This would protect against serde-based logging while maintaining explicit serialization for configuration files through wrapper types when needed.

Additionally, add linting rules or code review guidelines to prevent logging of sensitive types without explicit Debug (`?`) formatting.

## Proof of Concept

```rust
use aptos_crypto::secp256r1_ecdsa::PrivateKey;
use aptos_crypto::traits::Uniform;
use aptos_logger::info;
use serde::Serialize;

#[derive(Serialize)]
struct Config {
    private_key: PrivateKey,
}

fn main() {
    aptos_logger::Logger::builder().build();
    
    let mut rng = rand::rngs::OsRng;
    let private_key = PrivateKey::generate(&mut rng);
    
    let config = Config { private_key };
    
    // This will expose the private key in hex format in logs
    info!(config = config);
    
    // This is safe - uses SilentDebug
    info!(safe_config = ?config);
}
```

**Expected vulnerable output:**
```json
{"level":"info", "data": {"config": {"private_key": "0x1234...abcd"}}}
```

**Expected safe output:**
```json
{"level":"info", "data": {"safe_config": "<elided secret for PrivateKey>"}}
```

---

**Notes:**

The `SilentDebug` and `SilentDisplay` macros are correctly implemented for their intended purpose. The vulnerability is a **design gap** where serde serialization provides an alternate code path that bypasses the protection. This is a latent vulnerability that could be triggered by developer error rather than an active exploit in the current codebase.

### Citations

**File:** crates/aptos-crypto/src/secp256r1_ecdsa/secp256r1_ecdsa_keys.rs (L24-24)
```rust
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L128-143)
```rust
#[proc_macro_derive(SilentDebug)]
pub fn silent_debug(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    quote! {
        // In order to ensure that secrets are never leaked, Debug is elided
        impl #impl_generics ::std::fmt::Debug for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "<elided secret for {}>", stringify!(#name))
            }
        }
    }
    .into()
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L196-199)
```rust
                if serializer.is_human_readable() {
                    self.to_encoded_string()
                        .map_err(<S::Error as ::serde::ser::Error>::custom)
                        .and_then(|str| serializer.serialize_str(&str[..]))
```

**File:** crates/aptos-crypto/src/traits/mod.rs (L102-104)
```rust
    fn to_encoded_string(&self) -> Result<String> {
        Ok(format!("0x{}", ::hex::encode(self.to_bytes())))
    }
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L167-187)
```rust
        impl Visitor for JsonVisitor<'_> {
            fn visit_pair(&mut self, key: Key, value: Value<'_>) {
                let v = match value {
                    Value::Debug(d) => serde_json::Value::String(
                        TruncatedLogString::from(format!("{:?}", d)).into(),
                    ),
                    Value::Display(d) => {
                        serde_json::Value::String(TruncatedLogString::from(d.to_string()).into())
                    },
                    Value::Serde(s) => match serde_json::to_value(s) {
                        Ok(value) => value,
                        Err(e) => {
                            // Log and skip the value that can't be serialized
                            eprintln!("error serializing structured log: {} for key {:?}", e, key);
                            return;
                        },
                    },
                };

                self.0.insert(key, v);
            }
```

**File:** crates/aptos-logger/src/macros.rs (L152-156)
```rust
    (@ { $(,)* $($out:expr),* }, $($k:ident).+ = $val:expr, $($args:tt)*) => {
        $crate::schema!(
            @ { $($out),*, &$crate::KeyValue::new($crate::__log_stringify!($($k).+), $crate::Value::from_serde(&$val)) },
            $($args)*
        )
```

**File:** config/src/config/identity_config.rs (L24-46)
```rust
#[derive(Deserialize, Serialize)]
pub struct IdentityBlob {
    /// Optional account address. Used for validators and validator full nodes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_address: Option<AccountAddress>,
    /// Optional account key. Only used for validators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_private_key: Option<Ed25519PrivateKey>,
    /// Optional consensus key. Only used for validators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_private_key: Option<bls12381::PrivateKey>,
    /// Network private key. Peer id is derived from this if account address is not present
    pub network_private_key: x25519::PrivateKey,
}

impl IdentityBlob {
    pub fn from_file(path: &Path) -> anyhow::Result<IdentityBlob> {
        Ok(serde_yaml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn to_file(&self, path: &Path) -> anyhow::Result<()> {
        let mut file = File::open(path)?;
        Ok(file.write_all(serde_yaml::to_string(self)?.as_bytes())?)
```
