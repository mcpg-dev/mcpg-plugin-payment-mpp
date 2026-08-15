//! # mcpg-plugin-payment-mpp
//!
//! Machine Payment Protocol (MPP) payment plugin for the MCPG gateway.
//!
//! This is the canonical MPP payment implementation, extracted into a standalone
//! plugin crate that implements both `ToolGatePlugin` and `PaymentAwarePlugin`.
//!
//! ## How it works
//!
//! 1. Per-binding charge configs are compiled at construction (static or CEL expr)
//! 2. On pre-dispatch, resolves the charge for the tool call
//! 3. If no credential in `_meta` → issues an HMAC-bound challenge
//! 4. If credential present → verifies HMAC, expiry, and amount → receipt or deny

mod expr;

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mcpg_plugin_protocol::{
    GateDecision, PluginClass, PluginContext, PluginManifest, ToolGatePlugin, async_trait,
    payment::{PaymentAwarePlugin, PaymentCapability, PaymentCategory, PaymentProtocol},
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use expr::{DynamicValue, ExprContext};

const PLUGIN_ID: &str = "dev.mcpg.payment.mpp";

/// Domain-separation tag for the settlement-proof signature. The
/// settlement authority signs `SETTLEMENT_BINDING_V1 | realm | tool |
/// amount | currency | recipient | nonce`; the gateway verifies that
/// signature with the operator-configured public key before granting.
const SETTLEMENT_BINDING_V1: &str = "mpp-settlement-v1";

/// Upper bound on the challenge validity window. A long window widens the
/// payment replay surface, so an over-large value is rejected at boot.
const MAX_CHALLENGE_TIMEOUT_SECONDS: u64 = 3600;

// ---------------------------------------------------------------------------
// Config types (operator-facing)
// ---------------------------------------------------------------------------

/// Payment configuration — top-level payment section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentPluginConfig {
    pub enabled: bool,
    /// HMAC secret value. The operator populates this from `${env.X}` or
    /// `cred://…`, which the gateway substitutes to the literal secret at
    /// config load; the plugin reads the resolved value directly.
    pub secret_key: String,
    /// Server realm for challenges.
    #[serde(default = "default_realm")]
    pub realm: String,
    /// Default recipient address.
    #[serde(default)]
    pub recipient: String,
    /// Challenge validity window, in seconds (max 3600).
    #[serde(default = "default_timeout")]
    pub challenge_timeout_seconds: u64,

    /// Hex-encoded (64 char) Ed25519 public key of the settlement
    /// authority that signs proofs of payment. When set, a credential
    /// is accepted only if `payload.signature` is a valid signature
    /// over the payment binding for the challenge's nonce. When unset
    /// (and `allow_unverified` is false) the gate fails closed: a tool
    /// call is DENIED because no proof of payment can be verified.
    #[serde(default)]
    pub settlement_public_key: Option<String>,

    /// INSECURE escape hatch. When true, credentials are accepted on
    /// challenge integrity alone (no settlement signature) — i.e. an
    /// echoed challenge grants access. Only for dev/testing against a
    /// trusted client. Defaults to false; logs a loud WARN when on.
    #[serde(default)]
    pub allow_unverified: bool,

    /// Per-tool charge configurations.
    #[serde(default)]
    pub tools: BTreeMap<String, ToolChargeConfig>,
}

fn default_realm() -> String {
    "mcpg-gateway".into()
}

fn default_timeout() -> u64 {
    300
}

impl Default for PaymentPluginConfig {
    /// Matches the empty / absent (`{}`) config block: the plugin is
    /// DISABLED (`enabled: false`), so `from_config` yields a no-op gate
    /// — the same behaviour the old fail-open parse produced for an empty
    /// or missing block. The remaining fields mirror the `#[serde(default
    /// = "...")]` attributes so a config that only sets `enabled`
    /// deserialises identically to `Default::default()` with that field
    /// overridden.
    fn default() -> Self {
        Self {
            enabled: false,
            secret_key: String::new(),
            realm: default_realm(),
            recipient: String::new(),
            challenge_timeout_seconds: default_timeout(),
            settlement_public_key: None,
            allow_unverified: false,
            tools: BTreeMap::new(),
        }
    }
}

/// Per-tool charge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolChargeConfig {
    /// Charge amount — literal decimal or CEL expression (e.g. `"0.10"` or `"${arguments.count > 10 ? \"1.00\" : \"0.10\"}"`)
    pub charge: String,
    /// Currency code (defaults to "USDC").
    #[serde(default)]
    pub currency: Option<String>,
    /// Override recipient for this tool.
    #[serde(default)]
    pub recipient: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal charge config (compiled)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BackendChargeConfig {
    charge: DynamicValue<String>,
    charge_source: String,
    currency: Option<String>,
    recipient: Option<String>,
}

impl BackendChargeConfig {
    fn resolve_charge(&self, ctx: &ExprContext) -> Result<String> {
        self.charge.resolve(ctx)
    }
}

// ---------------------------------------------------------------------------
// Payment gate plugin
// ---------------------------------------------------------------------------

/// Machine Payment Protocol (MPP) plugin.
///
/// Implements `ToolGatePlugin` to integrate with the gateway plugin chain.
/// Can be loaded as a native plugin or used directly.
pub struct PaymentGatePlugin {
    manifest: PluginManifest,
    enabled: bool,
    binding_charges: BTreeMap<String, BackendChargeConfig>,
    secret_key: String,
    realm: String,
    default_recipient: String,
    challenge_timeout_seconds: u64,
    /// Settlement-authority public key. `None` => no proof can be
    /// verified (fail closed unless `allow_unverified`).
    settlement_key: Option<VerifyingKey>,
    /// INSECURE: accept credentials without a settlement signature.
    allow_unverified: bool,
    /// Redeemed challenge nonces (single-use). Maps nonce -> challenge
    /// expiry, so a credential cannot be replayed within its validity
    /// window. In-process only; clustered single-use is a follow-up.
    redeemed: Mutex<HashMap<String, time::OffsetDateTime>>,
}

impl PaymentGatePlugin {
    /// Create a disabled (no-op) payment plugin.
    pub fn disabled() -> Self {
        Self {
            manifest: Self::make_manifest(),
            enabled: false,
            binding_charges: BTreeMap::new(),
            secret_key: String::new(),
            realm: String::new(),
            default_recipient: String::new(),
            challenge_timeout_seconds: 300,
            settlement_key: None,
            allow_unverified: false,
            redeemed: Mutex::new(HashMap::new()),
        }
    }

    /// Create a payment plugin from config.
    pub fn from_config(config: &PaymentPluginConfig) -> Result<Self> {
        if !config.enabled {
            return Ok(Self::disabled());
        }

        let secret_key = config.secret_key.clone();
        if secret_key.is_empty() {
            return Err(anyhow::anyhow!("payment.secret_key is not set or empty"));
        }

        let realm = if config.realm.is_empty() {
            "mcpg-gateway".to_owned()
        } else {
            config.realm.clone()
        };

        let settlement_key = match config.settlement_public_key.as_deref() {
            Some(hex_key) if !hex_key.trim().is_empty() => {
                Some(parse_settlement_key(hex_key.trim())?)
            }
            _ => None,
        };

        // Bound the challenge validity window: a long window widens the
        // payment replay surface, and the seconds-named field invites a
        // 1000×-too-large value, so reject out-of-range at boot.
        if config.challenge_timeout_seconds == 0 {
            anyhow::bail!("payment.challenge_timeout_seconds must be greater than 0");
        }
        if config.challenge_timeout_seconds > MAX_CHALLENGE_TIMEOUT_SECONDS {
            anyhow::bail!(
                "payment.challenge_timeout_seconds {} exceeds the maximum of {} seconds; \
                 a long challenge window widens the payment replay window",
                config.challenge_timeout_seconds,
                MAX_CHALLENGE_TIMEOUT_SECONDS
            );
        }

        // Secure-by-default posture: refuse the dangerous combination and
        // make the fail-closed (or insecure-opt-in) state loud at boot.
        if settlement_key.is_none() {
            if config.allow_unverified {
                warn!(
                    plugin_id = PLUGIN_ID,
                    "payment-mpp: 'allow_unverified' is ENABLED — credentials are accepted on \
                     challenge integrity alone (NO proof of payment). Insecure; dev/testing only."
                );
            } else {
                warn!(
                    plugin_id = PLUGIN_ID,
                    "payment-mpp: no 'settlement_public_key' configured — all paid tool calls \
                     will be DENIED because no proof of payment can be verified. Set \
                     settlement_public_key to accept payments."
                );
            }
        }

        let mut binding_charges = BTreeMap::new();
        for (tool_name, tool_cfg) in &config.tools {
            let charge_dv = DynamicValue::parse(&tool_cfg.charge).map_err(|e| {
                anyhow::anyhow!(
                    "failed to compile charge expression for tool '{}': {}",
                    tool_name,
                    e,
                )
            })?;
            binding_charges.insert(
                tool_name.clone(),
                BackendChargeConfig {
                    charge: charge_dv,
                    charge_source: tool_cfg.charge.clone(),
                    currency: tool_cfg.currency.clone(),
                    recipient: tool_cfg.recipient.clone(),
                },
            );
        }

        Ok(Self {
            manifest: Self::make_manifest(),
            enabled: true,
            binding_charges,
            secret_key,
            realm,
            default_recipient: config.recipient.clone(),
            challenge_timeout_seconds: config.challenge_timeout_seconds,
            settlement_key,
            allow_unverified: config.allow_unverified,
            redeemed: Mutex::new(HashMap::new()),
        })
    }

    fn make_manifest() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            name: "Machine Payment Protocol (MPP)".into(),
            plugin_class: PluginClass::ToolGate,
            protocol_version: "1.0".into(),
            license: None,
            required_capabilities: Vec::new(),
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!()
                .split("::")
                .next()
                .unwrap_or("")
                .to_owned(),
            backend_profile: None,
        }
    }

    /// SDK macro factory: parses operator config JSON.
    ///
    /// Fails CLOSED on a present-but-malformed config: a non-empty,
    /// unparseable `config:` block panics (via the SDK convention helper),
    /// which the FFI `make` slot turns into a boot rejection rather than
    /// silently loading a wide-open / disabled plugin. An empty / absent
    /// block (`""`/`"{}"`/`"null"`) still yields `Default` — a DISABLED
    /// gate — because that is an explicit opt-out, not a typo.
    ///
    /// A *parsed* config whose runtime compile fails (e.g. a bad charge
    /// expression or settlement key) is still loaded as DISABLED with a
    /// loud error: that is a validation concern distinct from the
    /// parse-level fail-closed gate.
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg: PaymentPluginConfig =
            mcpg_plugin_sdk::fail_closed_config!(config_json, PaymentPluginConfig);
        Self::from_config(&cfg).unwrap_or_else(|err| {
            tracing::error!(
                error = %err,
                "payment-mpp: config compile failed; loading as DISABLED"
            );
            Self::disabled()
        })
    }

    /// Evaluate a tool call for payment requirements.
    fn evaluate_tool_call(
        &self,
        tool_name: &str,
        arguments: &Value,
        meta: Option<&Value>,
    ) -> InternalEvaluation {
        if !self.enabled {
            return InternalEvaluation::NotRequired;
        }

        let charge_config = match self.binding_charges.get(tool_name) {
            Some(cfg) => cfg,
            None => return InternalEvaluation::NotRequired,
        };

        let expr_ctx = ExprContext {
            arguments: arguments.clone(),
            tool_name: tool_name.to_owned(),
        };

        let effective_charge = match charge_config.resolve_charge(&expr_ctx) {
            Ok(c) => c,
            Err(err) => {
                warn!(
                    tool_name = %tool_name,
                    charge = %charge_config.charge_source,
                    error = %err,
                    "charge expression evaluation failed"
                );
                return InternalEvaluation::Failed(format!(
                    "charge expression evaluation failed: {}",
                    err,
                ));
            }
        };

        // Validate the resolved charge is a positive decimal
        match effective_charge.trim().parse::<f64>() {
            Ok(v) if v > 0.0 && v.is_finite() => {}
            _ => {
                warn!(
                    tool_name = %tool_name,
                    resolved_charge = %effective_charge,
                    "charge evaluated to an invalid amount"
                );
                return InternalEvaluation::Failed(format!(
                    "charge evaluated to invalid amount: '{}'",
                    effective_charge,
                ));
            }
        }

        let credential_value = meta.and_then(|m| m.get("org.paymentauth/credential"));

        match credential_value {
            None => self.issue_challenge(tool_name, charge_config, &effective_charge),
            Some(cred_json) => self.verify_credential(tool_name, &effective_charge, cred_json),
        }
    }

    /// Build an HMAC-bound payment challenge. The challenge ID is an HMAC over
    /// (realm, method, intent, tool, request, nonce, expires) so only this
    /// server can produce a valid ID; clients cannot forge one and a challenge
    /// issued for one tool cannot be replayed against another. The request
    /// field encodes the charge amount/currency/recipient as base64url JSON;
    /// the nonce is a server-generated random token that binds the eventual
    /// settlement proof to this specific challenge and makes it single-use.
    fn issue_challenge(
        &self,
        tool_name: &str,
        charge_config: &BackendChargeConfig,
        effective_charge: &str,
    ) -> InternalEvaluation {
        let recipient = charge_config
            .recipient
            .as_deref()
            .unwrap_or(&self.default_recipient);
        let currency = charge_config.currency.as_deref().unwrap_or("USDC");

        let expires = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(self.challenge_timeout_seconds as i64);
        let expires_str = expires
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();

        let nonce = random_nonce();

        let request_data = serde_json::json!({
            "amount": effective_charge,
            "currency": currency,
            "recipient": recipient,
        });

        let request_b64 = base64_url_encode(&serde_json::to_vec(&request_data).unwrap_or_default());
        let challenge_id = compute_challenge_hmac(
            &self.secret_key,
            &self.realm,
            "tempo",
            "charge",
            tool_name,
            &request_b64,
            &nonce,
            Some(&expires_str),
        );

        let challenge_data = serde_json::json!({
            "httpStatus": 402,
            "challenges": [{
                "id": challenge_id,
                "realm": self.realm,
                "method": "tempo",
                "intent": "charge",
                "request": request_b64,
                "nonce": nonce,
                "expires": expires_str,
                "description": format!("Payment required for tool '{}'", tool_name),
            }]
        });

        InternalEvaluation::ChallengeRequired {
            _challenge_id: challenge_id,
            challenge_data,
        }
    }

    /// Verify a client-supplied payment credential.
    ///
    /// Defence in depth, in order:
    /// 1. **Challenge integrity** — the challenge ID is an HMAC over the
    ///    realm/method/intent/**tool**/request/**nonce**/expires, recomputed
    ///    with constant-time compare, so only this server could have issued
    ///    it and only for this tool.
    /// 2. **Expiry** — the challenge must be within its validity window.
    /// 3. **Amount** — the challenge's amount must equal the current charge.
    /// 4. **Proof of payment** — a settlement-authority Ed25519 signature over
    ///    the payment binding (tool/amount/currency/recipient/nonce) MUST
    ///    verify against the configured key. Without a configured key the gate
    ///    fails closed (Deny) — an echoed challenge alone never grants. The
    ///    legacy accept-on-assertion behaviour is available only behind the
    ///    explicit, loudly-logged `allow_unverified` opt-in.
    /// 5. **Single use** — the challenge nonce is recorded on success and
    ///    rejected on replay within its validity window.
    fn verify_credential(
        &self,
        tool_name: &str,
        effective_charge: &str,
        credential_json: &Value,
    ) -> InternalEvaluation {
        let challenge = match credential_json.get("challenge") {
            Some(c) => c,
            None => {
                return InternalEvaluation::Failed(
                    "credential missing 'challenge' field".to_owned(),
                );
            }
        };

        let challenge_id = match challenge.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                return InternalEvaluation::Failed(
                    "credential challenge missing 'id' field".to_owned(),
                );
            }
        };

        let realm = challenge
            .get("realm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let method = challenge
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let intent = challenge
            .get("intent")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let request = challenge
            .get("request")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let nonce = challenge
            .get("nonce")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expires = challenge.get("expires").and_then(|v| v.as_str());

        // (1) Challenge integrity — bound to the *current* tool_name, so a
        // challenge issued for another tool fails here.
        let expected_id = compute_challenge_hmac(
            &self.secret_key,
            realm,
            method,
            intent,
            tool_name,
            request,
            nonce,
            expires,
        );

        if !constant_time_eq(challenge_id, &expected_id) {
            warn!(
                tool_name = %tool_name,
                payment_method = %method,
                "payment credential challenge ID mismatch"
            );
            return InternalEvaluation::Failed(
                "challenge ID mismatch — not issued by this server for this tool".to_owned(),
            );
        }

        // (2) Expiry.
        if let Some(expires_str) = expires
            && let Ok(expires_at) = time::OffsetDateTime::parse(
                expires_str,
                &time::format_description::well_known::Rfc3339,
            )
            && expires_at <= time::OffsetDateTime::now_utc()
        {
            warn!(
                tool_name = %tool_name,
                payment_method = %method,
                payment_challenge_id = %challenge_id,
                "payment challenge expired"
            );
            return InternalEvaluation::Failed(format!("challenge expired at {}", expires_str));
        }

        // (3) Amount + decode the binding fields (currency/recipient) from the
        // HMAC-protected request blob.
        let (req_amount, currency, recipient) = match base64_url_decode(request)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        {
            Some(rd) => (
                rd.get("amount")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                rd.get("currency")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                rd.get("recipient")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
            ),
            None => (String::new(), String::new(), String::new()),
        };
        if req_amount != effective_charge {
            warn!(
                tool_name = %tool_name,
                expected_amount = %effective_charge,
                credential_amount = %req_amount,
                "payment amount mismatch"
            );
            return InternalEvaluation::Failed(format!(
                "amount mismatch: credential has '{}' but tool requires '{}'",
                req_amount, effective_charge,
            ));
        }

        // (4) Proof of payment — the security-critical gate. Without a verified
        // settlement signature, fail closed.
        let reference = match self.verify_settlement_proof(
            tool_name,
            &req_amount,
            &currency,
            &recipient,
            nonce,
            credential_json,
        ) {
            Ok(reference) => reference,
            Err(reason) => {
                warn!(
                    tool_name = %tool_name,
                    payment_method = %method,
                    payment_challenge_id = %challenge_id,
                    reason = %reason,
                    "payment proof verification failed"
                );
                return InternalEvaluation::Failed(reason);
            }
        };

        // (5) Single use — reject replay of an already-redeemed challenge.
        if let Err(reason) = self.record_nonce_once(nonce, expires) {
            warn!(
                tool_name = %tool_name,
                payment_challenge_id = %challenge_id,
                "payment credential replay rejected"
            );
            return InternalEvaluation::Failed(reason);
        }

        let receipt_meta = serde_json::json!({
            "org.paymentauth/receipt": {
                "status": "success",
                "method": method,
                "challengeId": challenge_id,
                "reference": reference,
            }
        });

        InternalEvaluation::Verified {
            _challenge_id: challenge_id.to_owned(),
            receipt_meta,
        }
    }

    /// Verify the settlement proof carried in `credential.payload`. Returns the
    /// receipt reference on success.
    ///
    /// - With a configured settlement key: requires `payload.signature` (hex
    ///   Ed25519) over the canonical payment binding; rejects otherwise.
    /// - Without a key, only `allow_unverified` (insecure opt-in) accepts; the
    ///   default is fail-closed Deny.
    fn verify_settlement_proof(
        &self,
        tool_name: &str,
        amount: &str,
        currency: &str,
        recipient: &str,
        nonce: &str,
        credential_json: &Value,
    ) -> std::result::Result<String, String> {
        let payload = credential_json.get("payload");

        match &self.settlement_key {
            Some(key) => {
                let sig_hex = payload
                    .and_then(|p| p.get("signature"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        "missing proof of payment: credential.payload.signature is required"
                            .to_owned()
                    })?;
                let sig_bytes: [u8; 64] = hex::decode(sig_hex)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| {
                        "proof of payment signature is not a 64-byte hex Ed25519 signature"
                            .to_owned()
                    })?;
                let binding =
                    settlement_binding(&self.realm, tool_name, amount, currency, recipient, nonce);
                let signature = Signature::from_bytes(&sig_bytes);
                key.verify(binding.as_bytes(), &signature).map_err(|_| {
                    "proof of payment signature did not verify against the settlement key"
                        .to_owned()
                })?;
                // Receipt reference: an opaque settlement reference if the
                // client supplied one, else the verified signature.
                let reference = payload
                    .and_then(|p| p.get("reference"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| format!("ed25519:{}", &sig_hex[..sig_hex.len().min(32)]));
                Ok(reference)
            }
            None if self.allow_unverified => {
                metrics::counter!(
                    "mcpg_payment_mpp_unverified_accept_total",
                    "tool" => tool_name.to_owned(),
                )
                .increment(1);
                warn!(
                    plugin_id = PLUGIN_ID,
                    tool_name = %tool_name,
                    "payment-mpp: accepting credential WITHOUT proof of payment \
                     (allow_unverified=true)"
                );
                Ok("unverified".to_owned())
            }
            None => Err(
                "no settlement verifier configured: this gateway cannot verify a proof of \
                 payment, so the call is denied (set payment.settlement_public_key)"
                    .to_owned(),
            ),
        }
    }

    /// Record a challenge nonce as redeemed, rejecting a replay. Prunes expired
    /// entries opportunistically to bound memory.
    fn record_nonce_once(
        &self,
        nonce: &str,
        expires: Option<&str>,
    ) -> std::result::Result<(), String> {
        if nonce.is_empty() {
            // A legitimately-issued challenge always carries a nonce; its
            // absence means a stale/forged challenge shape.
            return Err("challenge missing nonce — cannot enforce single use".to_owned());
        }
        let now = time::OffsetDateTime::now_utc();
        let expires_at = expires
            .and_then(|s| {
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
            })
            .unwrap_or_else(|| {
                now + time::Duration::seconds(self.challenge_timeout_seconds as i64)
            });

        let mut redeemed = match self.redeemed.lock() {
            Ok(g) => g,
            // Poisoned lock: fail closed rather than risk a double-spend.
            Err(_) => return Err("payment replay store unavailable".to_owned()),
        };
        redeemed.retain(|_, exp| *exp > now);
        if redeemed.contains_key(nonce) {
            return Err("payment credential already redeemed (replay)".to_owned());
        }
        redeemed.insert(nonce.to_owned(), expires_at);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal evaluation enum (not public — maps to GateDecision)
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum InternalEvaluation {
    NotRequired,
    ChallengeRequired {
        _challenge_id: String,
        challenge_data: Value,
    },
    Verified {
        _challenge_id: String,
        receipt_meta: Value,
    },
    Failed(String),
}

// ---------------------------------------------------------------------------
// ToolGatePlugin implementation
// ---------------------------------------------------------------------------

/// JSON-RPC error code for payment required (402).
///
/// MCP 2025-11-25 reserves `-32042` for `URLElicitationRequiredError`,
/// so MCPG-specific payment codes live above the reserved `-32000..-32099`
/// JSON-RPC + MCP range. See also `apps/gateway/src/protocol/mod.rs`.
const PAYMENT_REQUIRED_CODE: i32 = -33042;
/// JSON-RPC error code for payment verification failure.
const PAYMENT_VERIFICATION_FAILED_CODE: i32 = -33043;

impl SyncToolGate for PaymentGatePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        // Payment gating applies to tool calls only.
        if ctx.surface != "tool" {
            return GateDecision::allow();
        }
        // Plugin-scoped span so traces from the MPP payment gate
        // attribute back to dev.mcpg.payment.mpp.
        let _span = tracing::info_span!(
            "mpp_payment_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();
        let started = std::time::Instant::now();
        let evaluation = self.evaluate_tool_call(&ctx.tool_name, arguments, meta);
        let outcome = match &evaluation {
            InternalEvaluation::NotRequired => "not_required",
            InternalEvaluation::ChallengeRequired { .. } => "challenge",
            InternalEvaluation::Verified { .. } => "verified",
            InternalEvaluation::Failed(_) => "failed",
        };
        metrics::counter!(
            "mcpg_payment_mpp_evaluations_total",
            "outcome" => outcome,
        )
        .increment(1);
        metrics::histogram!("mcpg_payment_mpp_evaluate_ms")
            .record(started.elapsed().as_millis() as f64);
        match evaluation {
            InternalEvaluation::NotRequired => GateDecision::allow(),
            InternalEvaluation::ChallengeRequired { challenge_data, .. } => {
                GateDecision::Challenge {
                    http_status: 402,
                    code: PAYMENT_REQUIRED_CODE,
                    message: format!("Payment Required for tool '{}'", ctx.tool_name),
                    challenge_data,
                }
            }
            InternalEvaluation::Verified { receipt_meta, .. } => {
                GateDecision::allow_with_metadata(receipt_meta)
            }
            InternalEvaluation::Failed(reason) => {
                tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    tool = %ctx.tool_name,
                    reason = %reason,
                    "mpp payment verification failed"
                );
                GateDecision::Deny {
                    http_status: 403,
                    code: PAYMENT_VERIFICATION_FAILED_CODE,
                    message: format!("Payment Verification Failed: {reason}"),
                    error_data: None,
                }
            }
        }
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &Value,
        _result: &Value,
        _duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        // MPP has no post-dispatch logic — default Allow.
        GateDecision::allow()
    }
}

/// Async `ToolGatePlugin` impl — kept for the gateway's static-link
/// path. `PaymentAwarePlugin` is bounded on `ToolGatePlugin`, so the
/// gateway-side payment dispatch needs this trait. Delegates to the
/// sync `SyncToolGate::evaluate_pre` for the same body.
#[async_trait]
impl ToolGatePlugin for PaymentGatePlugin {
    fn manifest(&self) -> &PluginManifest {
        SyncToolGate::manifest(self)
    }

    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        config: &Value,
    ) -> GateDecision {
        SyncToolGate::evaluate_pre(self, ctx, arguments, meta, config)
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: PaymentGatePlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| PaymentGatePlugin::from_config_json(cfg),
        }
    ],
}

// ---------------------------------------------------------------------------
// PaymentAwarePlugin implementation
// ---------------------------------------------------------------------------

impl PaymentAwarePlugin for PaymentGatePlugin {
    fn payment_capabilities(&self) -> Vec<PaymentCapability> {
        vec![PaymentCapability {
            protocol: PaymentProtocol::Mpp,
            methods: vec!["tempo".into()],
            supports_sessions: true,
            supports_commerce: false,
            meta_prefix: "org.paymentauth/".into(),
        }]
    }

    fn credential_meta_keys(&self) -> Vec<String> {
        vec!["org.paymentauth/credential".into()]
    }

    fn payment_category(&self) -> PaymentCategory {
        PaymentCategory::ToolGate
    }

    fn configured_tools(&self) -> Vec<String> {
        self.binding_charges.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Crypto / encoding helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn compute_challenge_hmac(
    secret: &str,
    realm: &str,
    method: &str,
    intent: &str,
    tool: &str,
    request: &str,
    nonce: &str,
    expires: Option<&str>,
) -> String {
    // `tool` and `nonce` are part of the MAC so a challenge cannot be replayed
    // against a different tool and each challenge is uniquely identified.
    let message = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        realm,
        method,
        intent,
        tool,
        request,
        nonce,
        expires.unwrap_or("")
    );
    let hash = hmac_sha256::HMAC::mac(message.as_bytes(), secret.as_bytes());
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Canonical message the settlement authority signs to prove payment was made
/// for a specific challenge. Domain-separated and bound to every field that
/// determines the charge so a proof cannot be ported to a different
/// tool/amount/recipient/challenge.
fn settlement_binding(
    realm: &str,
    tool: &str,
    amount: &str,
    currency: &str,
    recipient: &str,
    nonce: &str,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        SETTLEMENT_BINDING_V1, realm, tool, amount, currency, recipient, nonce
    )
}

/// Parse a hex-encoded 32-byte Ed25519 public key.
fn parse_settlement_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key)
        .map_err(|e| anyhow::anyhow!("settlement_public_key is not valid hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("settlement_public_key must be 32 bytes (64 hex chars)"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("settlement_public_key is not a valid Ed25519 key: {e}"))
}

/// A 128-bit random nonce, hex-encoded, from the OS CSPRNG.
fn random_nonce() -> String {
    let mut buf = [0u8; 16];
    // getrandom only fails if the OS RNG is unavailable; fall back to a
    // time-derived value so challenge issuance never panics (the nonce's
    // security role is uniqueness + single-use, which time preserves).
    if getrandom::getrandom(&mut buf).is_err() {
        let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        buf[..16].copy_from_slice(&nanos.to_le_bytes());
    }
    hex::encode(buf)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use mcpg_plugin_protocol::PluginClass;

    const TEST_REALM: &str = "test.example.com";
    const TEST_RECIPIENT: &str = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2";
    /// Deterministic settlement-authority key for tests.
    const TEST_SETTLEMENT_SEED: [u8; 32] = [7u8; 32];

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SETTLEMENT_SEED)
    }

    fn test_settlement_key() -> VerifyingKey {
        test_signing_key().verifying_key()
    }

    fn charges() -> BTreeMap<String, BackendChargeConfig> {
        let mk = || BackendChargeConfig {
            charge: DynamicValue::Literal("0.10".to_owned()),
            charge_source: "0.10".to_owned(),
            currency: Some("USDC".to_owned()),
            recipient: None,
        };
        BTreeMap::from([
            ("premium_tool".to_owned(), mk()),
            ("premium_tool2".to_owned(), mk()),
        ])
    }

    /// Plugin configured the secure way: a settlement verifier key is set, so
    /// a valid proof of payment is required.
    fn test_plugin() -> PaymentGatePlugin {
        PaymentGatePlugin {
            manifest: PaymentGatePlugin::make_manifest(),
            enabled: true,
            binding_charges: charges(),
            secret_key: "test-secret-key-for-hmac".to_owned(),
            realm: TEST_REALM.to_owned(),
            default_recipient: TEST_RECIPIENT.to_owned(),
            challenge_timeout_seconds: 300,
            settlement_key: Some(test_settlement_key()),
            allow_unverified: false,
            redeemed: Mutex::new(HashMap::new()),
        }
    }

    /// Plugin with no settlement key and no opt-in: must fail closed.
    fn fail_closed_plugin() -> PaymentGatePlugin {
        PaymentGatePlugin {
            settlement_key: None,
            allow_unverified: false,
            ..test_plugin()
        }
    }

    /// Plugin with the insecure escape hatch enabled.
    fn allow_unverified_plugin() -> PaymentGatePlugin {
        PaymentGatePlugin {
            settlement_key: None,
            allow_unverified: true,
            ..test_plugin()
        }
    }

    /// Issue a challenge and return the single challenge object.
    fn issue_challenge_for(plugin: &PaymentGatePlugin, ctx: &PluginContext) -> Value {
        match plugin.evaluate_pre(ctx, &serde_json::json!({}), None, &serde_json::json!({})) {
            GateDecision::Challenge { challenge_data, .. } => {
                challenge_data["challenges"][0].clone()
            }
            other => panic!("expected challenge, got: {:?}", other),
        }
    }

    /// Build a `_meta` credential carrying a valid settlement signature for the
    /// given challenge, signed for `tool`.
    fn signed_credential_meta(challenge: &Value, tool: &str) -> Value {
        let nonce = challenge["nonce"].as_str().unwrap();
        let req = base64_url_decode(challenge["request"].as_str().unwrap()).unwrap();
        let rd: Value = serde_json::from_slice(&req).unwrap();
        let binding = settlement_binding(
            TEST_REALM,
            tool,
            rd["amount"].as_str().unwrap(),
            rd["currency"].as_str().unwrap(),
            rd["recipient"].as_str().unwrap(),
            nonce,
        );
        let sig = test_signing_key().sign(binding.as_bytes());
        serde_json::json!({
            "org.paymentauth/credential": {
                "challenge": challenge.clone(),
                "payload": { "signature": hex::encode(sig.to_bytes()), "reference": "settlement-ref-123" }
            }
        })
    }

    fn test_ctx() -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-1".into(),
            session_id: None,
            tool_name: "premium_tool".into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    #[test]
    fn disabled_plugin_allows() {
        let plugin = PaymentGatePlugin::disabled();
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn free_tool_allows() {
        let plugin = test_plugin();
        let mut ctx = test_ctx();
        ctx.tool_name = "free_tool".into();
        let decision =
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
        assert!(decision.is_allow());
    }

    #[test]
    fn paid_tool_without_credential_issues_challenge() {
        let plugin = test_plugin();
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        match decision {
            GateDecision::Challenge {
                http_status,
                code,
                challenge_data,
                ..
            } => {
                assert_eq!(http_status, 402);
                assert_eq!(code, PAYMENT_REQUIRED_CODE);
                let challenges = challenge_data["challenges"].as_array().unwrap();
                assert_eq!(challenges.len(), 1);
                assert_eq!(challenges[0]["realm"], "test.example.com");
                assert_eq!(challenges[0]["method"], "tempo");
            }
            other => panic!("expected Challenge, got: {:?}", other),
        }
    }

    /// A credential carrying a valid settlement-authority signature over the
    /// challenge binding is accepted (the legitimate happy path).
    #[test]
    fn valid_settlement_signature_verifies() {
        let plugin = test_plugin();
        let challenge = issue_challenge_for(&plugin, &test_ctx());
        let meta = signed_credential_meta(&challenge, "premium_tool");

        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        match decision {
            GateDecision::Allow { metadata, .. } => {
                let meta = metadata.expect("should have receipt metadata");
                assert_eq!(meta["org.paymentauth/receipt"]["status"], "success");
                assert_eq!(
                    meta["org.paymentauth/receipt"]["reference"],
                    "settlement-ref-123"
                );
            }
            other => panic!("expected Allow with metadata, got: {:?}", other),
        }
    }

    /// Regression: an attacker who
    /// simply echoes the server-issued 402 challenge back — with a fabricated
    /// `payload` and NO settlement signature — must NOT be granted access. This
    /// is the exact bypass the old `verify_credential` allowed.
    #[test]
    fn echoed_challenge_without_proof_is_denied() {
        let plugin = test_plugin();
        let challenge = issue_challenge_for(&plugin, &test_ctx());

        // The pre-fix exploit: replay the challenge with a made-up payload.hash.
        let meta = serde_json::json!({
            "org.paymentauth/credential": {
                "challenge": challenge,
                "source": "did:pkh:eip155:42161:0xabc",
                "payload": { "hash": "0xtxhash123" }
            }
        });

        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(
            !decision.is_allow(),
            "echoing the server's own challenge must not grant access"
        );
    }

    /// Regression: a valid challenge with a forged/garbage settlement
    /// signature is denied — the signature must actually verify.
    #[test]
    fn forged_settlement_signature_is_denied() {
        let plugin = test_plugin();
        let challenge = issue_challenge_for(&plugin, &test_ctx());
        let meta = serde_json::json!({
            "org.paymentauth/credential": {
                "challenge": challenge,
                "payload": { "signature": hex::encode([0xABu8; 64]) }
            }
        });
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(
            !decision.is_allow(),
            "a non-verifying signature must be denied"
        );
    }

    /// Regression: with no settlement verifier configured the gate fails
    /// CLOSED — even a perfectly-formed, server-issued challenge is denied,
    /// because the gateway cannot verify a proof of payment.
    #[test]
    fn fail_closed_when_no_settlement_key() {
        let plugin = fail_closed_plugin();
        let challenge = issue_challenge_for(&plugin, &test_ctx());
        let meta = serde_json::json!({
            "org.paymentauth/credential": { "challenge": challenge, "payload": {} }
        });
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(
            !decision.is_allow(),
            "no settlement verifier must fail closed, not open"
        );
    }

    /// The insecure escape hatch (`allow_unverified`) is the ONLY way an echoed
    /// challenge is accepted without a signature — documents/guards the opt-in.
    #[test]
    fn allow_unverified_opt_in_accepts_echoed_challenge() {
        let plugin = allow_unverified_plugin();
        let challenge = issue_challenge_for(&plugin, &test_ctx());
        let meta = serde_json::json!({
            "org.paymentauth/credential": { "challenge": challenge, "payload": {} }
        });
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(
            decision.is_allow(),
            "allow_unverified must accept an echoed challenge (insecure dev mode)"
        );
    }

    /// Regression: a valid credential is single-use — accepted
    /// once, then rejected on replay within the validity window.
    #[test]
    fn replayed_credential_is_denied() {
        let plugin = test_plugin();
        let challenge = issue_challenge_for(&plugin, &test_ctx());
        let meta = signed_credential_meta(&challenge, "premium_tool");

        let first = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(first.is_allow(), "first redemption should succeed");

        let second = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(
            !second.is_allow(),
            "replay of the same credential must be denied"
        );
    }

    /// Regression: a credential issued for one tool
    /// cannot be redeemed against a different tool (the HMAC binds the tool),
    /// even when the charge amount is identical.
    #[test]
    fn credential_bound_to_other_tool_is_denied() {
        let plugin = test_plugin();
        // Challenge + signature minted for premium_tool.
        let challenge = issue_challenge_for(&plugin, &test_ctx());
        let meta = signed_credential_meta(&challenge, "premium_tool");

        // Present it on a call to premium_tool2 (also 0.10).
        let mut ctx = test_ctx();
        ctx.tool_name = "premium_tool2".into();
        let decision = plugin.evaluate_pre(
            &ctx,
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(
            !decision.is_allow(),
            "a challenge issued for premium_tool must not satisfy premium_tool2"
        );
    }

    #[test]
    fn tampered_challenge_denied() {
        let plugin = test_plugin();
        let meta = serde_json::json!({
            "org.paymentauth/credential": {
                "challenge": {
                    "id": "tampered-fake-id",
                    "realm": "test.example.com",
                    "method": "tempo",
                    "intent": "charge",
                    "request": base64_url_encode(b"{\"amount\":\"0.10\",\"currency\":\"USDC\"}"),
                },
                "payload": { "hash": "0xfake" }
            }
        });
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(!decision.is_allow());
    }

    #[test]
    fn expired_challenge_denied() {
        let plugin = test_plugin();
        let past = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        let expires_str = past
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let request_data = serde_json::json!({"amount": "0.10", "currency": "USDC", "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"});
        let request_b64 = base64_url_encode(&serde_json::to_vec(&request_data).unwrap());
        let nonce = "expired-nonce";
        let challenge_id = compute_challenge_hmac(
            "test-secret-key-for-hmac",
            "test.example.com",
            "tempo",
            "charge",
            "premium_tool",
            &request_b64,
            nonce,
            Some(&expires_str),
        );
        let meta = serde_json::json!({
            "org.paymentauth/credential": {
                "challenge": {
                    "id": challenge_id,
                    "realm": "test.example.com",
                    "method": "tempo",
                    "intent": "charge",
                    "request": request_b64,
                    "nonce": nonce,
                    "expires": expires_str,
                },
                "payload": { "hash": "0xtx" }
            }
        });
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(!decision.is_allow());
    }

    #[test]
    fn amount_mismatch_denied() {
        let plugin = test_plugin();
        let expires = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        let expires_str = expires
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        // Wrong amount — 999.00 vs expected 0.10
        let request_data = serde_json::json!({"amount": "999.00", "currency": "USDC", "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"});
        let request_b64 = base64_url_encode(&serde_json::to_vec(&request_data).unwrap());
        let nonce = "mismatch-nonce";
        let challenge_id = compute_challenge_hmac(
            "test-secret-key-for-hmac",
            "test.example.com",
            "tempo",
            "charge",
            "premium_tool",
            &request_b64,
            nonce,
            Some(&expires_str),
        );
        let meta = serde_json::json!({
            "org.paymentauth/credential": {
                "challenge": {
                    "id": challenge_id,
                    "realm": "test.example.com",
                    "method": "tempo",
                    "intent": "charge",
                    "request": request_b64,
                    "nonce": nonce,
                    "expires": expires_str,
                },
                "payload": { "hash": "0xtx" }
            }
        });
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );
        assert!(!decision.is_allow());
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = test_plugin();
        let m = SyncToolGate::manifest(&plugin);
        assert_eq!(m.id, "dev.mcpg.payment.mpp");
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
        assert_eq!(m.protocol_version, "1.0");
    }

    #[test]
    fn hmac_is_deterministic() {
        let a = compute_challenge_hmac("secret", "realm", "m", "i", "tool", "r", "n", Some("e"));
        let b = compute_challenge_hmac("secret", "realm", "m", "i", "tool", "r", "n", Some("e"));
        assert_eq!(a, b);
        let c = compute_challenge_hmac("other", "realm", "m", "i", "tool", "r", "n", Some("e"));
        assert_ne!(a, c);
        // Tool binding: same inputs, different tool => different MAC.
        let d = compute_challenge_hmac("secret", "realm", "m", "i", "tool2", "r", "n", Some("e"));
        assert_ne!(a, d);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"hello payment world";
        let encoded = base64_url_encode(data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn from_config_disabled() {
        let config = PaymentPluginConfig {
            enabled: false,
            secret_key: "N/A".into(),
            realm: "test".into(),
            recipient: String::new(),
            challenge_timeout_seconds: 300,
            settlement_public_key: None,
            allow_unverified: false,
            tools: BTreeMap::new(),
        };
        let plugin = PaymentGatePlugin::from_config(&config).unwrap();
        assert!(!plugin.enabled);
        let decision = plugin.evaluate_pre(
            &test_ctx(),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn from_config_parses_settlement_key_and_round_trips() {
        let pubkey_hex = hex::encode(test_settlement_key().to_bytes());
        let config = PaymentPluginConfig {
            enabled: true,
            secret_key: "s3cr3t".into(),
            realm: "rt".into(),
            recipient: "acct:platform".into(),
            challenge_timeout_seconds: 300,
            settlement_public_key: Some(pubkey_hex),
            allow_unverified: false,
            tools: BTreeMap::from([(
                "premium_tool".to_owned(),
                ToolChargeConfig {
                    charge: "0.10".into(),
                    currency: Some("USDC".into()),
                    recipient: None,
                },
            )]),
        };
        let plugin = PaymentGatePlugin::from_config(&config).expect("config should compile");
        assert!(plugin.enabled);
        assert!(plugin.settlement_key.is_some());
    }

    #[test]
    fn from_config_rejects_bad_settlement_key() {
        let config = PaymentPluginConfig {
            enabled: true,
            secret_key: "s3cr3t".into(),
            realm: "rt".into(),
            recipient: String::new(),
            challenge_timeout_seconds: 300,
            settlement_public_key: Some("not-hex!!".into()),
            allow_unverified: false,
            tools: BTreeMap::new(),
        };
        assert!(PaymentGatePlugin::from_config(&config).is_err());
    }

    #[test]
    fn post_dispatch_defaults_to_allow() {
        let plugin = test_plugin();
        let decision = plugin.evaluate_post(
            &test_ctx(),
            &serde_json::json!({}),
            &serde_json::json!({"content": []}),
            100,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn payment_aware_capabilities() {
        let plugin = test_plugin();
        let caps = plugin.payment_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].protocol, PaymentProtocol::Mpp);
        assert_eq!(caps[0].methods, vec!["tempo"]);
        assert!(caps[0].supports_sessions);
        assert!(!caps[0].supports_commerce);
        assert_eq!(caps[0].meta_prefix, "org.paymentauth/");
    }

    #[test]
    fn payment_aware_category() {
        let plugin = test_plugin();
        assert_eq!(plugin.payment_category(), PaymentCategory::ToolGate);
    }

    #[test]
    fn payment_aware_credential_keys() {
        let plugin = test_plugin();
        let keys = plugin.credential_meta_keys();
        assert_eq!(keys, vec!["org.paymentauth/credential"]);
    }

    #[test]
    fn payment_aware_configured_tools() {
        let plugin = test_plugin();
        let tools = plugin.configured_tools();
        assert_eq!(tools, vec!["premium_tool", "premium_tool2"]);
    }

    /// Regression guard: MCP 2025-11-25 reserves -32042 for
    /// URLElicitationRequiredError. Ensure MPP no longer collides.
    #[test]
    fn payment_codes_outside_mcp_reserved_range() {
        const MCP_RESERVED_LO: i32 = -32099;
        const MCP_RESERVED_HI: i32 = -32000;
        for code in [PAYMENT_REQUIRED_CODE, PAYMENT_VERIFICATION_FAILED_CODE] {
            assert!(
                !(MCP_RESERVED_LO..=MCP_RESERVED_HI).contains(&code),
                "payment error code {code} collides with MCP reserved range [-32099, -32000]"
            );
        }
    }

    // -- fail-closed config parsing -----------------------------------------

    /// An empty / absent config block opts the operator out: the plugin
    /// loads as DISABLED (allows everything) rather than refusing to boot.
    #[test]
    fn empty_config_yields_disabled_default() {
        for block in ["", "{}", "null"] {
            let plugin = PaymentGatePlugin::from_config_json(block);
            assert!(
                !plugin.enabled,
                "empty config block {block:?} should yield a DISABLED gate"
            );
            assert!(
                plugin
                    .evaluate_pre(
                        &test_ctx(),
                        &serde_json::json!({}),
                        None,
                        &serde_json::json!({})
                    )
                    .is_allow(),
                "disabled gate from {block:?} must allow"
            );
        }
    }

    /// A present-but-malformed config block must FAIL CLOSED: the parse
    /// panics (the FFI `make` slot converts this into a boot rejection)
    /// rather than silently degrading to a disabled gate.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn malformed_config_fails_closed() {
        let _ = PaymentGatePlugin::from_config_json("not json");
    }

    /// An unknown / typo'd / renamed top-level config key must FAIL CLOSED
    /// (`deny_unknown_fields`): a present-but-wrong key is a parse error, so
    /// the FFI `make` slot refuses the plugin at boot rather than silently
    /// ignoring it. A silently-dropped key on a payment gate could leave a
    /// security control (e.g. `settlement_public_key`) un-applied.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_config_key_fails_closed() {
        // `settlment_public_key` is a deliberate typo of `settlement_public_key`.
        let _ = PaymentGatePlugin::from_config_json(
            r#"{"enabled":true,"secret_key":"X","settlment_public_key":"deadbeef"}"#,
        );
    }

    /// A typo in a *nested* per-tool charge config is likewise rejected.
    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_nested_tool_config_key_fails_closed() {
        let _ = PaymentGatePlugin::from_config_json(
            r#"{"enabled":true,"secret_key":"X","tools":{"t":{"charge":"0.10","currancy":"USDC"}}}"#,
        );
    }
}
