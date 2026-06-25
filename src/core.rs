//! The pure (non-wasm-bindgen) implementation behind the wasm port.
//!
//! Everything here is plain Rust with no `#[wasm_bindgen]` attributes, so it compiles and runs on the
//! HOST as well as wasm. The thin `#[wasm_bindgen]` wrappers in `lib.rs` delegate to this. Splitting
//! it out is what lets the golden-vector tests (host `cargo test`) exercise the EXACT code path the
//! browser runs — wasm-bindgen's generated shims panic ("not implemented on non-wasm32 targets") if
//! you try to call a `#[wasm_bindgen]` method on the host, so the testable logic must live off them.
//!
//! All vault orchestration + crypto is `ce_iam_core` (one implementation, golden-vectored); this file
//! only adapts it to a synchronous, snapshot-driven, string-in/string-out surface for JS, and runs
//! the async vault over the in-memory `MemStore` with a poll-once executor (the MemStore is always
//! Ready, so no async runtime is needed).

use std::cell::RefCell;
use std::future::Future;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use anyhow::{Context as _, Result, anyhow};
use ce_iam_core::secrets::{DeviceKey, MemStore, SecretMeta, Store, Vault};
use serde_json::{Map, Value};

// ---- a trivial poll-once executor ----------------------------------------------------------------
//
// Over a `MemStore` every future is Ready on the first poll (the in-memory map never suspends), so we
// avoid pulling tokio / wasm-bindgen-futures into the wasm graph. If a future were ever genuinely
// pending this panics loudly — the correct signal that someone wired a real async store in here.

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
    // Safety: the waker is fully no-op and never stored; this is the standard poll-once pattern.
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

// ---- the snapshot-driven vault core --------------------------------------------------------------

/// The pure vault implementation: a [`Vault`] over an in-memory snapshot, with the JS-facing
/// string/bytes surface. `lib.rs`'s `WasmVault` is a one-line-per-method wrapper over this.
pub struct VaultCore {
    inner: Vault<MemStore>,
    device_json: String,
    ns: String,
}

impl VaultCore {
    pub fn new(device_json: &str, ns: &str, now_iso: &str) -> Result<Self> {
        let device = DeviceKey::from_json(device_json)?;
        let now = now_iso.to_string();
        let inner = Vault::with_clock(MemStore::new(), device, ns, move || now.clone());
        Ok(Self {
            inner,
            device_json: device_json.to_string(),
            ns: ns.to_string(),
        })
    }

    pub fn generate_device_key() -> Result<String> {
        DeviceKey::generate().and_then(|d| d.to_json())
    }

    pub fn namespace(&self) -> String {
        self.ns.clone()
    }

    pub fn device_id(&self) -> String {
        self.inner.device().id.clone()
    }

    pub fn device_public(&self) -> Result<String> {
        let dk = DeviceKey::from_json(&self.device_json)?;
        Ok(serde_json::to_string(&dk.public())?)
    }

    // ---- snapshot sync ---------------------------------------------------------------------------

    pub fn load_snapshot(&self, snapshot_json: &str) -> Result<()> {
        let map: Map<String, Value> = serde_json::from_str(snapshot_json)
            .context("parse snapshot JSON (expected an object of key -> record)")?;
        block_on(async {
            for e in self.inner.store().list("").await? {
                self.inner.store().del(&e.key).await?;
            }
            for (k, v) in map {
                self.inner.store().put(&k, v).await?;
            }
            Ok::<(), anyhow::Error>(())
        })
    }

    pub fn snapshot(&self) -> Result<String> {
        block_on(async {
            let mut out = Map::new();
            for e in self.inner.store().list("").await? {
                out.insert(e.key, e.value);
            }
            Ok(serde_json::to_string(&Value::Object(out))?)
        })
    }

    // ---- vault state -----------------------------------------------------------------------------

    pub fn exists(&self) -> Result<bool> {
        block_on(self.inner.exists())
    }
    pub fn is_enrolled(&self) -> Result<bool> {
        block_on(self.inner.is_enrolled())
    }
    pub fn init(&self, label: &str) -> Result<bool> {
        block_on(self.inner.init(label))
    }
    pub fn recover(&self, label: &str) -> Result<()> {
        block_on(self.inner.recover(label))
    }

    // ---- devices / pairing -----------------------------------------------------------------------

    pub fn request_pairing(&self, label: &str) -> Result<String> {
        block_on(self.inner.request_pairing(label))
    }
    pub fn list_pairing(&self) -> Result<String> {
        let v = block_on(self.inner.list_pairing())?;
        Ok(serde_json::to_string(&v)?)
    }
    pub fn approve_pairing(&self, code: &str) -> Result<String> {
        block_on(self.inner.approve_pairing(code))
    }
    pub fn list_devices(&self) -> Result<String> {
        let ds = block_on(self.inner.list_devices())?;
        let arr: Vec<Value> = ds
            .into_iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id, "label": d.label, "addedAt": d.added_at, "self": d.is_self,
                })
            })
            .collect();
        Ok(serde_json::to_string(&Value::Array(arr))?)
    }
    pub fn revoke_device(&self, id: &str) -> Result<()> {
        block_on(self.inner.revoke_device(id))
    }

    // ---- secrets ---------------------------------------------------------------------------------

    pub fn put_secret(&self, name: &str, bytes: &[u8], kind: &str) -> Result<String> {
        let m = block_on(self.inner.put_secret(name, bytes, kind))?;
        secret_meta_json(&m)
    }
    pub fn get_secret(&self, name: &str) -> Result<Vec<u8>> {
        Ok(block_on(self.inner.get_secret(name))?.bytes)
    }
    pub fn list_secrets(&self) -> Result<String> {
        let metas = block_on(self.inner.list_secrets())?;
        let arr: Vec<Value> = metas.iter().map(secret_meta_value).collect();
        Ok(serde_json::to_string(&Value::Array(arr))?)
    }
    pub fn fingerprint(&self, name: &str) -> Result<Option<String>> {
        block_on(self.inner.fingerprint(name))
    }
    pub fn delete_secret(&self, name: &str) -> Result<()> {
        block_on(self.inner.delete_secret(name))
    }

    // ---- grants ----------------------------------------------------------------------------------

    pub fn issue_grant(&self, audience: &str, names_json: &str, expires: &str) -> Result<String> {
        let read: Vec<String> = serde_json::from_str(names_json)
            .context("parse grant secret-names JSON (expected an array of strings)")?;
        let exp = (!expires.is_empty()).then(|| expires.to_string());
        let g = block_on(self.inner.issue_grant(audience, &read, exp))?;
        Ok(serde_json::to_string(&serde_json::json!({
            "id": g.id, "token": g.token, "record": g.record,
        }))?)
    }
    pub fn list_grants(&self) -> Result<String> {
        let v = block_on(self.inner.list_grants())?;
        Ok(serde_json::to_string(&v)?)
    }
    pub fn revoke_grant(&self, id: &str) -> Result<()> {
        block_on(self.inner.revoke_grant(id))
    }
    pub fn verify_grant(
        &self,
        token: &str,
        audience: &str,
        action: &str,
        name: &str,
        now_ms: i64,
    ) -> Result<()> {
        block_on(self.inner.verify_grant(token, audience, action, name, now_ms))
    }

    // ---- challenge-response auth -----------------------------------------------------------------

    pub fn sign_challenge(&self, aud: &str, nonce: &str, ts: &str) -> Result<String> {
        let proof = self.inner.sign_challenge(aud, nonce, ts)?;
        Ok(serde_json::to_string(&proof)?)
    }
    pub fn verify_auth(&self, aud: &str, nonce: &str, proof_json: &str) -> Result<String> {
        let proof: Value = serde_json::from_str(proof_json).context("parse auth proof JSON")?;
        block_on(self.inner.verify_auth(aud, nonce, &proof))
    }
}

fn secret_meta_value(m: &SecretMeta) -> Value {
    serde_json::json!({
        "name": m.name, "kind": m.kind, "version": m.version, "fp": m.fp,
        "public": m.public, "createdAt": m.created_at, "rotatedAt": m.rotated_at,
    })
}
fn secret_meta_json(m: &SecretMeta) -> Result<String> {
    Ok(serde_json::to_string(&secret_meta_value(m))?)
}

// ---- capability VERIFY ---------------------------------------------------------------------------

thread_local! {
    /// Per-call revocation set, threaded into `authorize`'s `is_revoked` (a plain fn that reads this
    /// rather than capturing). Set immediately before the `authorize` call, cleared after.
    static REVOKED: RefCell<Vec<(ce_identity::NodeId, u64)>> = const { RefCell::new(Vec::new()) };
}

fn parse_node_id(hex_id: &str) -> Result<ce_identity::NodeId> {
    let bytes = hex::decode(hex_id.trim()).context("node id is not valid hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("node id must be 32 bytes (64 hex chars)"))
}

/// Pure capability verify — the body behind the `verify` wasm export. Returns `Ok(())` if authorized,
/// `Err` with the denial reason otherwise (default-deny on an empty/invalid chain).
#[allow(clippy::too_many_arguments)]
pub fn verify_chain(
    self_id_hex: &str,
    accepted_roots_json: &str,
    self_tags_json: &str,
    now: u64,
    requester_hex: &str,
    action: &str,
    chain_json: &str,
    revoked_json: &str,
) -> Result<()> {
    let self_id = parse_node_id(self_id_hex)?;
    let requester = parse_node_id(requester_hex)?;

    let root_hexes: Vec<String> =
        serde_json::from_str(accepted_roots_json).context("parse accepted_roots JSON")?;
    let accepted_roots: Vec<ce_identity::NodeId> = root_hexes
        .iter()
        .map(|h| parse_node_id(h))
        .collect::<Result<_>>()?;

    let self_tags: Vec<String> =
        serde_json::from_str(self_tags_json).context("parse self_tags JSON")?;
    let chain: Vec<ce_cap::SignedCapability> =
        serde_json::from_str(chain_json).context("parse capability chain JSON")?;

    let revoked_pairs: Vec<(String, u64)> =
        serde_json::from_str(revoked_json).context("parse revoked JSON (array of [hex, nonce])")?;
    let revoked: Vec<(ce_identity::NodeId, u64)> = revoked_pairs
        .into_iter()
        .map(|(h, n)| parse_node_id(&h).map(|id| (id, n)))
        .collect::<Result<_>>()?;

    REVOKED.with(|r| *r.borrow_mut() = revoked);
    let is_revoked = |issuer: &ce_identity::NodeId, nonce: u64| -> bool {
        REVOKED.with(|r| r.borrow().iter().any(|(i, n)| i == issuer && *n == nonce))
    };

    let result = ce_cap::authorize(
        &self_id,
        &accepted_roots,
        &self_tags,
        now,
        &requester,
        action,
        &chain,
        &is_revoked,
    );
    REVOKED.with(|r| r.borrow_mut().clear());

    result.map_err(|reason| anyhow!(reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_on_resolves_ready_memstore_op() {
        let s = MemStore::new();
        block_on(async {
            s.put("k", serde_json::json!(1)).await.unwrap();
            assert_eq!(s.get("k").await.unwrap(), Some(serde_json::json!(1)));
        });
    }

    #[test]
    fn vault_roundtrip_native() {
        let dk = VaultCore::generate_device_key().unwrap();
        let v = VaultCore::new(&dk, "wasm-ns", "2026-06-26T00:00:00.000Z").unwrap();
        assert!(v.init("owner").unwrap());
        assert!(v.is_enrolled().unwrap());

        let meta = v.put_secret("api", b"s3cr3t", "opaque").unwrap();
        assert!(meta.contains("\"name\":\"api\""));
        assert_eq!(v.get_secret("api").unwrap(), b"s3cr3t");

        let snap = v.snapshot().unwrap();
        let v2 = VaultCore::new(&dk, "wasm-ns", "2026-06-26T00:00:00.000Z").unwrap();
        v2.load_snapshot(&snap).unwrap();
        assert!(v2.is_enrolled().unwrap());
        assert_eq!(v2.get_secret("api").unwrap(), b"s3cr3t");

        let g = v.issue_grant("ce-cast", "[\"api\"]", "").unwrap();
        let token = serde_json::from_str::<Value>(&g).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();
        v.verify_grant(&token, "ce-cast", "read", "api", 0).unwrap();
        assert!(v.verify_grant(&token, "other", "read", "api", 0).is_err());
    }
}
