# Machine Payment Protocol (MPP) — `dev.mcpg.payment.mpp`

> class `tool_gate` · `native` · package `mcpg-plugin-payment-mpp` · artifact `libmcpg_plugin_payment_mpp.so`

Machine Payment Protocol challenge/verify gate. Issues HTTP
402-style payment challenges for payment-gated tools and validates a
real **proof of payment** before letting the call proceed.
Per-tool charges may be a literal decimal or a CEL expression.

## What it does
- On pre-dispatch, resolves the charge for the tool (static or CEL),
  issues a server-signed challenge bound to the tool and a random
  single-use nonce, and denies until a valid proof is presented.
- The challenge ID is an HMAC-SHA256 over
  realm/method/intent/**tool**/request/**nonce**/expires
  (`secret_key`), so a challenge cannot be forged or replayed
  against a different tool.
- **Proof of payment is verified cryptographically.** The credential's
  `payload.signature` must be an Ed25519 signature, by the configured
  `settlement_public_key`, over the payment binding
  (`mpp-settlement-v1 | realm | tool | amount | currency | recipient |
  nonce`). A credential is **single-use** — its nonce is recorded and
  replays are denied within the validity window.
- **Fail-closed by default.** With no `settlement_public_key`
  configured the gate DENIES every paid tool call (it cannot verify a
  proof) and logs a loud WARN at boot. Echoing the server's own 402
  challenge back never grants access.
- Returns MPP-specific JSON-RPC error codes (`-33042` / `-33043`)
  outside the MCP-reserved range.
- Loads disabled when `enabled: false` or `secret_key` is unset.

> **Security note (single-use scope).** Replay protection is tracked
> per gateway process. In a clustered deployment a nonce redeemed on
> one node is not yet rejected on another; cluster-shared single-use is
> tracked as a follow-up. Bind the `challenge_timeout_seconds` window tight
> to limit exposure.

## Configuration
Loaded via the top-level `plugins:` list. The `config:` block is the
`PaymentPluginConfig` directly, with per-tool charges under `tools`.

```yaml
plugins:
  - id: dev.mcpg.payment.mpp
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_payment_mpp.so }
    config:
      enabled: true
      secret_key: ${env.MPP_SECRET_KEY}     # HMAC secret (gateway substitutes ${env.X}/cred://)
      realm: mcpg-gateway
      recipient: "acct:platform"            # default recipient
      challenge_timeout_seconds: 300
      # Ed25519 public key (hex, 64 chars) of the settlement authority
      # that signs proofs of payment. REQUIRED to accept payments; with
      # it unset the gate fails closed (denies all paid calls).
      settlement_public_key: "a1b2c3...e4f5"
      # allow_unverified: false             # INSECURE dev-only opt-in:
      #                                     # accept on challenge alone,
      #                                     # no proof of payment.
      tools:
        ai.premium_query:
          charge: "0.10"                     # literal, or a CEL expr like ${...}
          currency: USDC
          # recipient: "acct:other"          # per-tool override
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | — (required) | Master on/off switch. |
| `secret_key` | string | — (required) | HMAC secret value. Populate from `${env.X}` / `cred://…` (gateway-substituted at config load). |
| `realm` | string | `mcpg-gateway` | Server realm on challenges. |
| `recipient` | string | `""` | Default recipient address. |
| `challenge_timeout_seconds` | u64 | `300` | Challenge validity window in seconds (max 3600). |
| `settlement_public_key` | string? | `null` | Ed25519 settlement-authority public key (hex). Unset ⇒ **fail closed** (all paid calls denied). |
| `allow_unverified` | bool | `false` | **Insecure** dev-only: accept credentials with no proof of payment. Logs a loud WARN. |
| `tools.<name>.charge` | string | — | Literal decimal or CEL expression. |
| `tools.<name>.currency` | string? | `USDC` | Currency code. |
| `tools.<name>.recipient` | string? | global | Per-tool recipient override. |

## Build
```bash
cargo build -p mcpg-plugin-payment-mpp --features cdylib-export --release   # → target/release/libmcpg_plugin_payment_mpp.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
- Sibling payment gates: `libs/plugins/payment/{acp,ucp,x402}`
