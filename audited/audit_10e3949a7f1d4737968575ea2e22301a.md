# Audit Report

## Title
OpenAPI Schema Mismatch: CAPTCHA_KEY Header Not Set in Error Responses

## Summary
The OpenAPI schema for the `/request_captcha` endpoint incorrectly declares that the `CAPTCHA_KEY` header (type `u32`) is required in all responses, including error responses. However, the implementation only sets this header on successful responses, creating a schema-implementation mismatch that violates the API contract and could cause client-side parsing errors.

## Finding Description

The `/request_captcha` endpoint declares a response header at the endpoint level: [1](#0-0) 

This `response_header` attribute causes poem_openapi to generate OpenAPI schema that declares the `CAPTCHA_KEY` header as **required** for **all responses** from this endpoint, including both success (200) and error (default) responses: [2](#0-1) [3](#0-2) 

However, examining the implementation shows the header is only set in the success path: [4](#0-3) 

Error responses return `AptosTapErrorResponse`, which only defines the `Retry-After` header: [5](#0-4) 

The error response type does not include `CAPTCHA_KEY` as a header field, meaning error responses will be missing this header despite the OpenAPI schema declaring it as required.

## Impact Explanation

This is a **Low severity** API contract violation issue according to Aptos bug bounty criteria. The impact is limited to:

1. **Client SDK generation issues**: Auto-generated clients from the OpenAPI spec will expect the `CAPTCHA_KEY` header to always be present and attempt to parse it as a `u32`
2. **Client-side parsing errors**: When error responses are received without the header, client code may throw null reference exceptions or parsing failures
3. **API contract violation**: The actual API behavior does not match the documented contract

This does NOT affect:
- Blockchain consensus or safety
- State integrity or Merkle tree consistency  
- Transaction validation or execution
- Validator operations
- Fund security
- Any critical blockchain invariants

## Likelihood Explanation

This issue occurs **every time** the `/request_captcha` endpoint returns an error response (e.g., when the CaptchaChecker is disabled, or when captcha generation fails). Any client using auto-generated SDK code from the OpenAPI spec will encounter parsing errors when handling these error cases.

## Recommendation

**Option 1**: Remove the `response_header` declaration from the endpoint-level annotation and instead add the header only to the success response type. This would require creating a custom response wrapper type instead of using the generic `Response<Binary<Vec<u8>>>`.

**Option 2**: Modify `AptosTapErrorResponse` to include the `CAPTCHA_KEY` header field, though this doesn't make semantic sense since errors don't generate captcha keys. This approach is not recommended.

**Option 3** (Recommended): Change the OpenAPI schema to mark `CAPTCHA_KEY` as `required: false` to match the actual implementation. However, this requires understanding how poem_openapi generates schemas from the `response_header` attribute - it may not support optional headers at the endpoint level.

The cleanest fix is **Option 1**: restructure the response handling to only declare the header where it's actually set.

## Proof of Concept

This is not a security vulnerability requiring a PoC, but the issue can be demonstrated by:

1. Deploy the faucet with CaptchaChecker disabled
2. Call `/request_captcha` endpoint
3. Observe error response returns without `CAPTCHA_KEY` header
4. Compare against OpenAPI spec which declares the header as required
5. Use an auto-generated client (e.g., from openapi-generator) which will fail to parse the response

**Note**: While this is a valid API documentation issue that could cause client integration problems, it does **not** constitute a security vulnerability affecting the Aptos blockchain's consensus, state integrity, transaction validation, or fund security. It is a Low severity API contract violation with no impact on blockchain security invariants.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/captcha.rs (L37-37)
```rust
        response_header(name = "CAPTCHA_KEY", ty = "u32", description = "Captcha key"),
```

**File:** crates/aptos-faucet/core/src/endpoints/captcha.rs (L57-57)
```rust
        Ok(Response::new(Binary(image)).header(CAPTCHA_KEY, key))
```

**File:** crates/aptos-faucet/doc/spec.yaml (L71-77)
```yaml
            CAPTCHA_KEY:
              description: Captcha key
              required: true
              deprecated: false
              schema:
                type: integer
                format: uint32
```

**File:** crates/aptos-faucet/doc/spec.yaml (L84-91)
```yaml
          headers:
            CAPTCHA_KEY:
              description: Captcha key
              required: true
              deprecated: false
              schema:
                type: integer
                format: uint32
```

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L91-98)
```rust
#[derive(Debug, ApiResponse)]
pub enum AptosTapErrorResponse {
    Default(
        StatusCode,
        Json<AptosTapError>,
        #[oai(header = "Retry-After")] Option<u64>,
    ),
}
```
