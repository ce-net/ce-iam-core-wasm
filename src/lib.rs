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
//! `ce_iam_core::secrets::Vault` is generic over an async [`Store`](ce_iam_core::secrets::Store). In
//! the browser the durable store is the mesh KV (cast-control's `ce-kv/<ns>/1` service) reached over
//! the local CE node — that lives in **TypeScript**, not in wasm. So this port does NOT marshal an
//! async JS store across the wasm boundary (that path is slow and fragile). Instead:
//!
//!   1. TS loads the namespace's entries off the mesh KV and hands wasm a JSON snapshot.
//!   2. wasm runs the vault op over an in-memory [`MemStore`](ce_iam_core::secrets::MemStore) seeded
//!      from that snapshot (the MemStore never actually suspends, so a trivial poll-once executor
//!      drives the async vault with no runtime).
//!   3. wasm returns the result AND the (possibly mutated) snapshot; TS persists the diff to the mesh.
//!
//! All crypto + vault orchestration stays in Rust (one implementation, golden-vectored); only the
//! transport/persistence stays in TS. The `ce-iam-ts` SDK wraps this so callers see a normal
//! `{ get, put, del, list }` store interface.

use std::cell::RefCell;
use std::future::Future;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use ce_iam_core::secrets::{DeviceKey, MemStore, Store, Vault};
use serde_json::{Map, Value};
use wasm_bindgen::prelude::*;

/// Called once from JS (`init()`): route Rust panics to `console.error` for debuggability.
#[wasm_bindgen]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// ---- a trivial poll-once executor ----------------------------------------------------------------
//
// The vault is async, but over a `MemStore` every future is ready on the first poll (the in-memory
// map never suspends). So we don't need tokio/wasm-bindgen-futures in the wasm graph at all — we
// poll once with a no-op waker and unwrap the `Ready`. If a future were ever genuinely pending this
// would panic loudly, which is the correct signal that someone wired a real async store in here.

fn noop_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    let vtable = &RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(std::ptr::null(), vtable)
}

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = Box::pin(fut);
    // Safety: the waker is fully no-op and never stored; this is the standard "poll-once" pattern.
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!(
            "ce-iam-core-wasm: a vault op suspended over the in-memory snapshot store — the wasm \
             port only supports the synchronous MemStore (the durable store stays in TS)"
        ),
    }
}

fn js_err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

// ---- the snapshot-driven vault -------------------------------------------------------------------

/// A browser-side secrets vault: a [`Vault`](ce_iam_core::secrets::Vault) bound to one device key and
/// namespace, operating over an in-memory snapshot of the namespace's store entries.
///
/// Lifecycle from TS: construct with the device key + namespace, [`load_snapshot`](Self::load_snapshot)
/// the entries fetched off the mesh KV, run ops, then read [`snapshot`](Self::snapshot) back and
/// persist the diff. The injected `now()` (an ISO-8601 string, e.g. from `new Date().toISOString()`)
/// stamps records so the wasm never reaches `SystemTime` (which traps under wasm).
#[wasm_bindgen]
pub struct WasmVault {
    inner: Vault<MemStore>,
    device_json: String,
    ns: String,
}

#[wasm_bindgen]
impl WasmVault {
    /// Build a vault for `device_json` (a `DeviceKey` JSON bundle, the `generateDeviceKey()` form) in
    /// `ns`, stamping records with `now_iso` (an ISO-8601 UTC string). Start empty; call
    /// [`load_snapshot`](Self::load_snapshot) to seed it from the mesh store.
    #[wasm_bindgen(constructor)]
    pub fn new(device_json: &str, ns: &str, now_iso: &str) -> Result<WasmVault, JsValue> {
        let device = DeviceKey::from_json(device_json).map_err(js_err)?;
        let now = now_iso.to_string();
        let inner = Vault::with_clock(MemStore::new(), device, ns, move || now.clone());
        Ok(WasmVault {
            inner,
            device_json: device_json.to_string(),
            ns: ns.to_string(),
        })
    }

    /// Generate a fresh device key (two P-256 keypairs as JWKs + derived id), as the JS-compatible
    /// `DeviceKey` JSON string. Persist this in the browser (IndexedDB/localStorage); it is this
    /// device's identity in the vault.
    #[wasm_bindgen(js_name = generateDeviceKey)]
    pub fn generate_device_key() -> Result<String, JsValue> {
        DeviceKey::generate().and_then(|d| d.to_json()).map_err(js_err)
    }

    /// This vault's namespace.
    #[wasm_bindgen(getter)]
    pub fn namespace(&self) -> String {
        self.ns.clone()
    }

    /// This device's stable vault id.
    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> String {
        self.inner.device().id.clone()
    }

    /// This device's PUBLIC projection (`{id, ecdhPub, ecdsaPub}`) as JSON — safe to share (e.g. to
    /// publish a pairing request, or for a peer to enroll this device).
    #[wasm_bindgen(getter, js_name = devicePublic)]
    pub fn device_public(&self) -> Result<String, JsValue> {
        let dk = DeviceKey::from_json(&self.device_json).map_err(js_err)?;
        serde_json::to_string(&dk.public()).map_err(js_err)
    }

    // ---- snapshot sync ---------------------------------------------------------------------------

    /// Seed the in-memory store from a snapshot: a JSON object `{ "<key>": <value>, ... }` mapping
    /// every store key in the namespace to its record. Replaces any current contents. Call this with
    /// the entries fetched off the mesh KV before running ops.
    #[wasm_bindgen(js_name = loadSnapshot)]
    pub fn load_snapshot(&self, snapshot_json: &str) -> Result<(), JsValue> {
        let map: Map<String, Value> =
            serde_json::from_str(snapshot_json).map_err(js_err)?;
        block_on(async {
            // The MemStore has no clear(); rebuild it by deleting nothing and overwriting — but the
            // simplest correct path is to drain via list and del, then put. We del the existing keys
            // we can see, then put the snapshot.
            for e in self.inner.store().list("").await.map_err(js_err)? {
                self.inner.store().del(&e.key).await.map_err(js_err)?;
            }
            for (k, v) in map {
                self.inner.store().put(&k, v).await.map_err(js_err)?;
            }
            Ok::<(), JsValue>(())
        })
    }

    /// Export the current in-memory store as a snapshot JSON object `{ "<key>": <value>, ... }`. TS
    /// diffs this against what it loaded and persists the changed/new/removed keys to the mesh KV.
    #[wasm_bindgen(js_name = snapshot)]
    pub fn snapshot(&self) -> Result<String, JsValue> {
        block_on(async {
            let mut out = Map::new();
            for e in self.inner.store().list("").await.map_err(js_err)? {
                out.insert(e.key, e.value);
            }
            serde_json::to_string(&Value::Object(out)).map_err(js_err)
        })
    }

    // ---- vault state -----------------------------------------------------------------------------

    /// True if the vault has been initialised (a `meta` record exists in the snapshot).
    #[wasm_bindgen]
    pub fn exists(&self) -> Result<bool, JsValue> {
        block_on(self.inner.exists()).map_err(js_err)
    }

    /// True if THIS device is enrolled (can decrypt the master).
    #[wasm_bindgen(js_name = isEnrolled)]
    pub fn is_enrolled(&self) -> Result<bool, JsValue> {
        block_on(self.inner.is_enrolled()).map_err(js_err)
    }

    /// Establish the vault from this (owner) device. Returns `false` if one already exists.
    #[wasm_bindgen]
    pub fn init(&self, label: &str) -> Result<bool, JsValue> {
        block_on(self.inner.init(label)).map_err(js_err)
    }

    /// Re-establish the vault from the OWNER's key alone (re-derive the deterministic master, re-enroll
    /// this device). Idempotent; the recovery primitive.
    #[wasm_bindgen]
    pub fn recover(&self, label: &str) -> Result<(), JsValue> {
        block_on(self.inner.recover(label)).map_err(js_err)
    }

    // ---- devices / pairing -----------------------------------------------------------------------

    /// Publish a pairing request for this (unenrolled) device; returns the human-typable code an
    /// enrolled device approves with.
    #[wasm_bindgen(js_name = requestPairing)]
    pub fn request_pairing(&self, label: &str) -> Result<String, JsValue> {
        block_on(self.inner.request_pairing(label)).map_err(js_err)
    }

    /// List pending pairing requests as a JSON array.
    #[wasm_bindgen(js_name = listPairing)]
    pub fn list_pairing(&self) -> Result<String, JsValue> {
        let v = block_on(self.inner.list_pairing()).map_err(js_err)?;
        serde_json::to_string(&v).map_err(js_err)
    }

    /// Approve a pairing request (wrap the master to the new device, enroll it). Returns the enrolled
    /// device id.
    #[wasm_bindgen(js_name = approvePairing)]
    pub fn approve_pairing(&self, code: &str) -> Result<String, JsValue> {
        block_on(self.inner.approve_pairing(code)).map_err(js_err)
    }

    /// List enrolled devices as a JSON array of `{ id, label, addedAt, self }`.
    #[wasm_bindgen(js_name = listDevices)]
    pub fn list_devices(&self) -> Result<String, JsValue> {
        let ds = block_on(self.inner.list_devices()).map_err(js_err)?;
        let arr: Vec<Value> = ds
            .into_iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id,
                    "label": d.label,
                    "addedAt": d.added_at,
                    "self": d.is_self,
                })
            })
            .collect();
        serde_json::to_string(&Value::Array(arr)).map_err(js_err)
    }

    /// Remove a device's enrollment (refuses to revoke the device you are using).
    #[wasm_bindgen(js_name = revokeDevice)]
    pub fn revoke_device(&self, id: &str) -> Result<(), JsValue> {
        block_on(self.inner.revoke_device(id)).map_err(js_err)
    }

    // ---- secrets ---------------------------------------------------------------------------------

    /// Store opaque secret bytes under `name`, sealed under the master. Returns the public metadata as
    /// JSON (never the bytes).
    #[wasm_bindgen(js_name = putSecret)]
    pub fn put_secret(&self, name: &str, bytes: &[u8], kind: &str) -> Result<String, JsValue> {
        let m = block_on(self.inner.put_secret(name, bytes, kind)).map_err(js_err)?;
        secret_meta_json(&m)
    }

    /// Reveal the raw secret bytes — for INJECTION/USE only. Never display these.
    #[wasm_bindgen(js_name = getSecret)]
    pub fn get_secret(&self, name: &str) -> Result<Vec<u8>, JsValue> {
        Ok(block_on(self.inner.get_secret(name)).map_err(js_err)?.bytes)
    }

    /// List secret metadata (never bytes) as a JSON array, sorted by name.
    #[wasm_bindgen(js_name = listSecrets)]
    pub fn list_secrets(&self) -> Result<String, JsValue> {
        let metas = block_on(self.inner.list_secrets()).map_err(js_err)?;
        let arr: Vec<Value> = metas
            .iter()
            .map(|m| {
                serde_json::json!({
                    "name": m.name, "kind": m.kind, "version": m.version, "fp": m.fp,
                    "public": m.public, "createdAt": m.created_at, "rotatedAt": m.rotated_at,
                })
            })
            .collect();
        serde_json::to_string(&Value::Array(arr)).map_err(js_err)
    }

    /// The displayable fingerprint of a named secret, or `null`.
    #[wasm_bindgen]
    pub fn fingerprint(&self, name: &str) -> Result<Option<String>, JsValue> {
        block_on(self.inner.fingerprint(name)).map_err(js_err)
    }

    /// Delete a named secret.
    #[wasm_bindgen(js_name = deleteSecret)]
    pub fn delete_secret(&self, name: &str) -> Result<(), JsValue> {
        block_on(self.inner.delete_secret(name)).map_err(js_err)
    }

    // ---- grants ----------------------------------------------------------------------------------

    /// Issue a signed read-grant to `audience` for the given secret `names`, optionally expiring at
    /// `expires` (ISO-8601, or empty for none). Returns `{ id, token, record }` JSON.
    #[wasm_bindgen(js_name = issueGrant)]
    pub fn issue_grant(
        &self,
        audience: &str,
        names_json: &str,
        expires: &str,
    ) -> Result<String, JsValue> {
        let read: Vec<String> = serde_json::from_str(names_json).map_err(js_err)?;
        let exp = if expires.is_empty() {
            None
        } else {
            Some(expires.to_string())
        };
        let g = block_on(self.inner.issue_grant(audience, &read, exp)).map_err(js_err)?;
        serde_json::to_string(&serde_json::json!({
            "id": g.id, "token": g.token, "record": g.record,
        }))
        .map_err(js_err)
    }

    /// List issued grants as a JSON array.
    #[wasm_bindgen(js_name = listGrants)]
    pub fn list_grants(&self) -> Result<String, JsValue> {
        let v = block_on(self.inner.list_grants()).map_err(js_err)?;
        serde_json::to_string(&v).map_err(js_err)
    }

    /// Revoke (delete) an issued grant by id.
    #[wasm_bindgen(js_name = revokeGrant)]
    pub fn revoke_grant(&self, id: &str) -> Result<(), JsValue> {
        block_on(self.inner.revoke_grant(id)).map_err(js_err)
    }

    /// Verify a presented grant `token` authorizes `action` on secret `name` for `audience`, against
    /// THIS vault's enrolled devices and un-revoked grants. `now_ms` is the current unix-ms clock.
    /// Resolves (returns nothing) on success; throws with the reason otherwise.
    #[wasm_bindgen(js_name = verifyGrant)]
    pub fn verify_grant(
        &self,
        token: &str,
        audience: &str,
        action: &str,
        name: &str,
        now_ms: f64,
    ) -> Result<(), JsValue> {
        block_on(self.inner.verify_grant(token, audience, action, name, now_ms as i64))
            .map_err(js_err)
    }

    // ---- challenge-response auth -----------------------------------------------------------------

    /// This device signs a fresh challenge, proving it is an enrolled operator. Returns the auth proof
    /// (the wire object the relying party verifies) as JSON.
    #[wasm_bindgen(js_name = signChallenge)]
    pub fn sign_challenge(&self, aud: &str, nonce: &str, ts: &str) -> Result<String, JsValue> {
        let proof = self.inner.sign_challenge(aud, nonce, ts).map_err(js_err)?;
        serde_json::to_string(&proof).map_err(js_err)
    }

    /// Verify an auth proof (JSON): valid signature, signer enrolled, aud/nonce match. Returns the
    /// proven device id; throws otherwise.
    #[wasm_bindgen(js_name = verifyAuth)]
    pub fn verify_auth(&self, aud: &str, nonce: &str, proof_json: &str) -> Result<String, JsValue> {
        let proof: Value = serde_json::from_str(proof_json).map_err(js_err)?;
        block_on(self.inner.verify_auth(aud, nonce, &proof)).map_err(js_err)
    }
}

fn secret_meta_json(m: &ce_iam_core::secrets::SecretMeta) -> Result<String, JsValue> {
    serde_json::to_string(&serde_json::json!({
        "name": m.name, "kind": m.kind, "version": m.version, "fp": m.fp,
        "public": m.public, "createdAt": m.created_at, "rotatedAt": m.rotated_at,
    }))
    .map_err(js_err)
}

// ---- capability VERIFY ---------------------------------------------------------------------------

thread_local! {
    /// Per-call revocation set, threaded into `authorize`'s `is_revoked` closure (which is a plain fn
    /// pointer, so it reads this rather than capturing). Set immediately before `authorize`.
    static REVOKED: RefCell<Vec<(ce_identity::NodeId, u64)>> = const { RefCell::new(Vec::new()) };
}

fn parse_node_id(hex_id: &str) -> Result<ce_identity::NodeId, JsValue> {
    let bytes = hex::decode(hex_id.trim()).map_err(js_err)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("node id must be 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

/// Verify a presented capability chain authorizes `requester` to perform `action` on `self_id`.
///
/// Pure `ce_cap::authorize` — VERIFY only. Inputs are the same JSON shapes the node uses on the wire:
///   * `self_id_hex` / `requester_hex` — 32-byte node ids as hex.
///   * `accepted_roots_json` — JSON array of hex node ids this verifier trusts as roots (besides self).
///   * `self_tags_json` — JSON array of this node's tag strings (for tag-scoped resources).
///   * `chain_json` — JSON array of `SignedCapability` (the presented chain, root first).
///   * `revoked_json` — JSON array of `[issuerHex, nonce]` pairs known revoked (or `[]`).
///   * `now` — current unix seconds.
///
/// Returns `true` if authorized; throws a `JsValue` string with the denial reason otherwise (so the
/// caller can surface why a capability was rejected). Default-deny: an empty/invalid chain is denied.
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
    let self_id = parse_node_id(self_id_hex)?;
    let requester = parse_node_id(requester_hex)?;

    let root_hexes: Vec<String> = serde_json::from_str(accepted_roots_json).map_err(js_err)?;
    let accepted_roots: Vec<ce_identity::NodeId> = root_hexes
        .iter()
        .map(|h| parse_node_id(h))
        .collect::<Result<_, _>>()?;

    let self_tags: Vec<String> = serde_json::from_str(self_tags_json).map_err(js_err)?;
    let chain: Vec<ce_cap::SignedCapability> = serde_json::from_str(chain_json).map_err(js_err)?;

    let revoked_pairs: Vec<(String, u64)> = serde_json::from_str(revoked_json).map_err(js_err)?;
    let revoked: Vec<(ce_identity::NodeId, u64)> = revoked_pairs
        .into_iter()
        .map(|(h, n)| parse_node_id(&h).map(|id| (id, n)))
        .collect::<Result<_, _>>()?;

    REVOKED.with(|r| *r.borrow_mut() = revoked);
    let is_revoked = |issuer: &ce_identity::NodeId, nonce: u64| -> bool {
        REVOKED.with(|r| r.borrow().iter().any(|(i, n)| i == issuer && *n == nonce))
    };

    let result = ce_cap::authorize(
        &self_id,
        &accepted_roots,
        &self_tags,
        now as u64,
        &requester,
        action,
        &chain,
        &is_revoked,
    );
    REVOKED.with(|r| r.borrow_mut().clear());

    match result {
        Ok(()) => Ok(true),
        Err(reason) => Err(JsValue::from_str(&reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The golden-vector parity test against ce-secrets/src/crypto.mjs runs as a host (non-wasm) test
    // through the SAME fixtures the ce-iam-core golden test uses, but exercised THROUGH the wasm
    // bindings' inner code path. It lives in tests/golden_wasm.rs (an integration test) so it can
    // include the shared fixtures file.

    #[test]
    fn block_on_resolves_ready_memstore_op() {
        // A MemStore op is always Ready on the first poll, so block_on returns without panicking.
        let s = MemStore::new();
        block_on(async {
            s.put("k", serde_json::json!(1)).await.unwrap();
            assert_eq!(s.get("k").await.unwrap(), Some(serde_json::json!(1)));
        });
    }

    #[test]
    fn vault_roundtrip_through_wasm_struct() {
        // Drive the whole WasmVault surface natively (host build) to prove the bindings are wired
        // to the real vault: generate a key, init, put+get a secret, snapshot+reload, grant+verify.
        let dk = WasmVault::generate_device_key().unwrap();
        let v = WasmVault::new(&dk, "wasm-ns", "2026-06-26T00:00:00.000Z").unwrap();
        assert!(v.init("owner").unwrap());
        assert!(v.is_enrolled().unwrap());

        let meta = v.put_secret("api", b"s3cr3t", "opaque").unwrap();
        assert!(meta.contains("\"name\":\"api\""));
        assert_eq!(v.get_secret("api").unwrap(), b"s3cr3t");

        // Snapshot out, reload into a fresh vault with the SAME device key -> still enrolled & reads.
        let snap = v.snapshot().unwrap();
        let v2 = WasmVault::new(&dk, "wasm-ns", "2026-06-26T00:00:00.000Z").unwrap();
        v2.load_snapshot(&snap).unwrap();
        assert!(v2.is_enrolled().unwrap());
        assert_eq!(v2.get_secret("api").unwrap(), b"s3cr3t");

        // Grant + verify.
        let g = v.issue_grant("ce-cast", "[\"api\"]", "").unwrap();
        let token = serde_json::from_str::<Value>(&g).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();
        v.verify_grant(&token, "ce-cast", "read", "api", 0.0).unwrap();
        assert!(v.verify_grant(&token, "other", "read", "api", 0.0).is_err());
    }
}
