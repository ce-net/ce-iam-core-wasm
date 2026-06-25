//! # ce-iam-core-wasm — the browser port of `ce-iam-core` ("basic auth" in wasm)
//!
//! This crate exposes two things from the lightweight half of CE IAM to JavaScript, over the SAME
//! Rust code the native `ce-iam` CLI runs (so the browser and the CLI agree byte-for-byte, and the
//! golden vectors against `ce-secrets/src/crypto.mjs` cover both):
//!
//!   * **The secrets vault** ([`WasmVault`]) — open / recover / get / put / list / device pairing /
//!     issue+verify grant / challenge-response auth. Owner-derived master, ECIES-wrapped per device,
//!     AES-GCM-sealed secrets. This is what ce-cast (and any browser tab) uses instead of vendoring
//!     `vault.mjs`.
//!   * **Capability VERIFY** ([`verify`]) — run `ce_cap::authorize` over a presented capability chain.
//!     VERIFY only; minting authority lives in the big `ce-iam` crate and never enters the browser.
//!
//! ## The store split (why the vault here is snapshot-driven)
//!
//! `ce_iam_core::secrets::Vault` is generic over an async `Store`. In the browser the durable store
//! is the mesh KV (cast-control's `ce-kv/<ns>/1` service) reached over the local CE node — that lives
//! in **TypeScript**, not in wasm. So this port does NOT marshal an async JS store across the wasm
//! boundary (slow + fragile). Instead: TS loads the namespace's entries, hands wasm a JSON snapshot
//! ([`WasmVault::load_snapshot`]); wasm runs the op over an in-memory store and returns the result +
//! the mutated snapshot ([`WasmVault::snapshot`]); TS persists the diff to the mesh. All crypto +
//! orchestration stays in Rust (one implementation, golden-vectored); only transport stays in TS. The
//! `ce-iam-ts` SDK wraps this so callers see a normal `{ get, put, del, list }` store.
//!
//! ## Host vs wasm
//!
//! The real logic lives in [`core`] (no `#[wasm_bindgen]`), so host `cargo test` (and CI / ce-build)
//! exercise the exact code path the browser runs — including the golden-vector tests in
//! `tests/golden_wasm.rs`. The `#[wasm_bindgen]` types below are thin delegators that also map errors
//! to thrown `JsValue` strings.

mod core;

use wasm_bindgen::prelude::*;

pub use crate::core::{VaultCore, verify_chain};

/// Called once from JS (`init()`): route Rust panics to `console.error` for debuggability.
#[wasm_bindgen]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

fn js_err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// A browser-side secrets vault: a vault bound to one device key + namespace, operating over an
/// in-memory snapshot of the namespace's store entries (see the module docs for the store split).
#[wasm_bindgen]
pub struct WasmVault {
    inner: VaultCore,
}

#[wasm_bindgen]
impl WasmVault {
    /// Build a vault for `device_json` (a `DeviceKey` JSON bundle, the `generateDeviceKey()` form) in
    /// `ns`, stamping records with `now_iso` (an ISO-8601 UTC string, e.g. `new Date().toISOString()`
    /// — injected so wasm never reaches `SystemTime`). Start empty; call `loadSnapshot` to seed it.
    #[wasm_bindgen(constructor)]
    pub fn new(device_json: &str, ns: &str, now_iso: &str) -> Result<WasmVault, JsValue> {
        Ok(WasmVault {
            inner: VaultCore::new(device_json, ns, now_iso).map_err(js_err)?,
        })
    }

    /// Generate a fresh device key as the JS-compatible `DeviceKey` JSON string. Persist it in the
    /// browser; it is this device's identity in the vault.
    #[wasm_bindgen(js_name = generateDeviceKey)]
    pub fn generate_device_key() -> Result<String, JsValue> {
        VaultCore::generate_device_key().map_err(js_err)
    }

    /// This vault's namespace.
    #[wasm_bindgen(getter)]
    pub fn namespace(&self) -> String {
        self.inner.namespace()
    }

    /// This device's stable vault id.
    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> String {
        self.inner.device_id()
    }

    /// This device's PUBLIC projection (`{id, ecdhPub, ecdsaPub}`) as JSON — safe to share.
    #[wasm_bindgen(getter, js_name = devicePublic)]
    pub fn device_public(&self) -> Result<String, JsValue> {
        self.inner.device_public().map_err(js_err)
    }

    /// Seed the in-memory store from a snapshot JSON object `{ "<key>": <value>, ... }` (replaces the
    /// current contents). Call with the entries fetched off the mesh KV before running ops.
    #[wasm_bindgen(js_name = loadSnapshot)]
    pub fn load_snapshot(&self, snapshot_json: &str) -> Result<(), JsValue> {
        self.inner.load_snapshot(snapshot_json).map_err(js_err)
    }

    /// Export the current in-memory store as a snapshot JSON object `{ "<key>": <value>, ... }`.
    #[wasm_bindgen]
    pub fn snapshot(&self) -> Result<String, JsValue> {
        self.inner.snapshot().map_err(js_err)
    }

    /// True if the vault has been initialised (a `meta` record exists).
    #[wasm_bindgen]
    pub fn exists(&self) -> Result<bool, JsValue> {
        self.inner.exists().map_err(js_err)
    }

    /// True if THIS device is enrolled (can decrypt the master).
    #[wasm_bindgen(js_name = isEnrolled)]
    pub fn is_enrolled(&self) -> Result<bool, JsValue> {
        self.inner.is_enrolled().map_err(js_err)
    }

    /// Establish the vault from this (owner) device. Returns `false` if one already exists.
    #[wasm_bindgen]
    pub fn init(&self, label: &str) -> Result<bool, JsValue> {
        self.inner.init(label).map_err(js_err)
    }

    /// Re-establish the vault from the OWNER's key alone (re-derive the master, re-enroll). Idempotent.
    #[wasm_bindgen]
    pub fn recover(&self, label: &str) -> Result<(), JsValue> {
        self.inner.recover(label).map_err(js_err)
    }

    /// Publish a pairing request for this (unenrolled) device; returns the human-typable code.
    #[wasm_bindgen(js_name = requestPairing)]
    pub fn request_pairing(&self, label: &str) -> Result<String, JsValue> {
        self.inner.request_pairing(label).map_err(js_err)
    }

    /// List pending pairing requests as a JSON array.
    #[wasm_bindgen(js_name = listPairing)]
    pub fn list_pairing(&self) -> Result<String, JsValue> {
        self.inner.list_pairing().map_err(js_err)
    }

    /// Approve a pairing request (wrap the master to the new device, enroll it). Returns its id.
    #[wasm_bindgen(js_name = approvePairing)]
    pub fn approve_pairing(&self, code: &str) -> Result<String, JsValue> {
        self.inner.approve_pairing(code).map_err(js_err)
    }

    /// List enrolled devices as a JSON array of `{ id, label, addedAt, self }`.
    #[wasm_bindgen(js_name = listDevices)]
    pub fn list_devices(&self) -> Result<String, JsValue> {
        self.inner.list_devices().map_err(js_err)
    }

    /// Remove a device's enrollment (refuses to revoke the device you are using).
    #[wasm_bindgen(js_name = revokeDevice)]
    pub fn revoke_device(&self, id: &str) -> Result<(), JsValue> {
        self.inner.revoke_device(id).map_err(js_err)
    }

    /// Store opaque secret bytes under `name`, sealed under the master. Returns public metadata JSON.
    #[wasm_bindgen(js_name = putSecret)]
    pub fn put_secret(&self, name: &str, bytes: &[u8], kind: &str) -> Result<String, JsValue> {
        self.inner.put_secret(name, bytes, kind).map_err(js_err)
    }

    /// Reveal the raw secret bytes — for INJECTION/USE only. Never display these.
    #[wasm_bindgen(js_name = getSecret)]
    pub fn get_secret(&self, name: &str) -> Result<Vec<u8>, JsValue> {
        self.inner.get_secret(name).map_err(js_err)
    }

    /// List secret metadata (never bytes) as a JSON array, sorted by name.
    #[wasm_bindgen(js_name = listSecrets)]
    pub fn list_secrets(&self) -> Result<String, JsValue> {
        self.inner.list_secrets().map_err(js_err)
    }

    /// The displayable fingerprint of a named secret, or `null`.
    #[wasm_bindgen]
    pub fn fingerprint(&self, name: &str) -> Result<Option<String>, JsValue> {
        self.inner.fingerprint(name).map_err(js_err)
    }

    /// Delete a named secret.
    #[wasm_bindgen(js_name = deleteSecret)]
    pub fn delete_secret(&self, name: &str) -> Result<(), JsValue> {
        self.inner.delete_secret(name).map_err(js_err)
    }

    /// Issue a signed read-grant to `audience` for the secret `names_json` (JSON array of names),
    /// optionally expiring at `expires` (ISO-8601, or empty). Returns `{ id, token, record }` JSON.
    #[wasm_bindgen(js_name = issueGrant)]
    pub fn issue_grant(
        &self,
        audience: &str,
        names_json: &str,
        expires: &str,
    ) -> Result<String, JsValue> {
        self.inner.issue_grant(audience, names_json, expires).map_err(js_err)
    }

    /// List issued grants as a JSON array.
    #[wasm_bindgen(js_name = listGrants)]
    pub fn list_grants(&self) -> Result<String, JsValue> {
        self.inner.list_grants().map_err(js_err)
    }

    /// Revoke (delete) an issued grant by id.
    #[wasm_bindgen(js_name = revokeGrant)]
    pub fn revoke_grant(&self, id: &str) -> Result<(), JsValue> {
        self.inner.revoke_grant(id).map_err(js_err)
    }

    /// Verify a presented grant `token` authorizes `action` on secret `name` for `audience`, against
    /// THIS vault's enrolled devices + un-revoked grants. `now_ms` is the unix-ms clock. Throws on
    /// denial with the reason.
    #[wasm_bindgen(js_name = verifyGrant)]
    pub fn verify_grant(
        &self,
        token: &str,
        audience: &str,
        action: &str,
        name: &str,
        now_ms: f64,
    ) -> Result<(), JsValue> {
        self.inner
            .verify_grant(token, audience, action, name, now_ms as i64)
            .map_err(js_err)
    }

    /// This device signs a fresh challenge, proving it is an enrolled operator. Returns the auth proof
    /// JSON the relying party verifies.
    #[wasm_bindgen(js_name = signChallenge)]
    pub fn sign_challenge(&self, aud: &str, nonce: &str, ts: &str) -> Result<String, JsValue> {
        self.inner.sign_challenge(aud, nonce, ts).map_err(js_err)
    }

    /// Verify an auth proof (JSON): valid signature, signer enrolled, aud/nonce match. Returns the
    /// proven device id; throws otherwise.
    #[wasm_bindgen(js_name = verifyAuth)]
    pub fn verify_auth(&self, aud: &str, nonce: &str, proof_json: &str) -> Result<String, JsValue> {
        self.inner.verify_auth(aud, nonce, proof_json).map_err(js_err)
    }
}

/// Verify a presented capability chain authorizes `requester` to perform `action` on `self_id`.
///
/// Pure `ce_cap::authorize` — VERIFY only. Inputs are the same JSON shapes the node uses on the wire:
///   * `self_id_hex` / `requester_hex` — 32-byte node ids as hex.
///   * `accepted_roots_json` — JSON array of hex node ids trusted as roots (besides self).
///   * `self_tags_json` — JSON array of this node's tag strings (for tag-scoped resources).
///   * `chain_json` — JSON array of `SignedCapability` (root first).
///   * `revoked_json` — JSON array of `[issuerHex, nonce]` pairs known revoked (or `[]`).
///   * `now` — current unix seconds.
///
/// Returns `true` if authorized; throws a `JsValue` string with the denial reason otherwise.
/// Default-deny: an empty/invalid chain is denied.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify(
    self_id_hex: &str,
    accepted_roots_json: &str,
    self_tags_json: &str,
    now: f64,
    requester_hex: &str,
    action: &str,
    chain_json: &str,
    revoked_json: &str,
) -> Result<bool, JsValue> {
    verify_chain(
        self_id_hex,
        accepted_roots_json,
        self_tags_json,
        now as u64,
        requester_hex,
        action,
        chain_json,
        revoked_json,
    )
    .map(|()| true)
    .map_err(js_err)
}
