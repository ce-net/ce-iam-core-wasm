//! GOLDEN-VECTOR GATE for the wasm port — the browser vault must agree byte-for-byte with the
//! canonical JS vault (`ce-secrets/src/crypto.mjs` + `vault.mjs`), exercised THROUGH the wasm-bindgen
//! surface (`WasmVault`) rather than the raw `ce-iam-core` API.
//!
//! These are the SAME `fixtures/secrets_vectors.json` vectors the `ce-iam-core` golden test uses
//! (produced by driving the real JS vault over a fixed owner key + fixed clock). Here we seed a
//! `WasmVault` snapshot with the JS-produced enrollment / grant / secret records and prove the wasm
//! port:
//!   * VERIFIES the JS-signed challenge proof through `WasmVault::verifyAuth`.
//!   * VERIFIES the JS-issued grant token through `WasmVault::verifyGrant`.
//!   * OPENS the JS-sealed secret through `WasmVault::getSecret` (master-derived, AES-GCM).
//!   * derives the SAME owner master + device id the JS did.
//!
//! Run as host tests (the wasm-bindgen exports compile for the host via the `rlib` crate-type), so
//! `cargo test` / `ce-build ... test` cover them in CI without a browser. Passing here pins all five
//! interop traps end-to-end through the wasm bindings.

use ce_iam_core_wasm::WasmVault;
use serde_json::{Map, Value};

const VECTORS: &str = include_str!("fixtures/secrets_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("parse secrets_vectors.json")
}

/// Build a snapshot JSON object `{ key: value }` from the fixture's enrollment + grant records, so a
/// `WasmVault` constructed with the owner key sees the JS-produced state.
fn seed_snapshot(v: &Value, include_grant: bool) -> String {
    let mut m = Map::new();
    m.insert(
        v["enrollment"]["key"].as_str().unwrap().to_string(),
        v["enrollment"]["record"].clone(),
    );
    if include_grant {
        let id = v["grant"]["record"]["id"].as_str().unwrap();
        m.insert(format!("g.{id}"), v["grant"]["record"].clone());
    }
    serde_json::to_string(&Value::Object(m)).unwrap()
}

fn owner_vault(v: &Value, snapshot: &str) -> WasmVault {
    let owner_json = serde_json::to_string(&v["owner"]).unwrap();
    let ns = v["ns"].as_str().unwrap();
    let vault = WasmVault::new(&owner_json, ns, "2026-06-26T00:00:00.000Z")
        .expect("construct WasmVault from JS owner key");
    vault.load_snapshot(snapshot).expect("load JS snapshot");
    vault
}

#[test]
fn wasm_device_id_and_namespace_match_js() {
    let v = vectors();
    let vault = owner_vault(&v, &seed_snapshot(&v, false));
    assert_eq!(vault.device_id(), v["deviceId"].as_str().unwrap());
    assert_eq!(vault.namespace(), v["ns"].as_str().unwrap());
    // The owner is enrolled (its JS d.<id> record is in the snapshot).
    assert!(vault.is_enrolled().unwrap());
}

#[test]
fn wasm_verifies_the_js_signed_challenge() {
    let v = vectors();
    let vault = owner_vault(&v, &seed_snapshot(&v, false));
    let proof_json = serde_json::to_string(&v["challenge"]["proof"]).unwrap();
    let who = vault
        .verify_auth(
            v["challenge"]["aud"].as_str().unwrap(),
            v["challenge"]["nonce"].as_str().unwrap(),
            &proof_json,
        )
        .expect("the JS-signed challenge must verify through the wasm vault");
    assert_eq!(who, v["deviceId"].as_str().unwrap());

    // A tampered nonce is rejected.
    assert!(
        vault
            .verify_auth(v["challenge"]["aud"].as_str().unwrap(), "wrong-nonce", &proof_json)
            .is_err()
    );
}

#[test]
fn wasm_verifies_the_js_issued_grant_token() {
    let v = vectors();
    let vault = owner_vault(&v, &seed_snapshot(&v, true));
    vault
        .verify_grant(
            v["grant"]["token"].as_str().unwrap(),
            v["grant"]["audience"].as_str().unwrap(),
            v["grant"]["action"].as_str().unwrap(),
            v["grant"]["name"].as_str().unwrap(),
            0.0,
        )
        .expect("the JS-issued grant token must verify through the wasm vault");

    // Wrong audience denied.
    assert!(
        vault
            .verify_grant(
                v["grant"]["token"].as_str().unwrap(),
                "not-the-audience",
                v["grant"]["action"].as_str().unwrap(),
                v["grant"]["name"].as_str().unwrap(),
                0.0,
            )
            .is_err()
    );
}

#[test]
fn wasm_opens_the_js_sealed_secret() {
    // Seed the snapshot with the JS secret record under its `s.<name>` key and OPEN it through the
    // wasm vault — proving the owner-derived master + AES-GCM unseal agree with the JS reference.
    let v = vectors();
    let mut snap: Map<String, Value> =
        serde_json::from_str(&seed_snapshot(&v, false)).unwrap();
    let name = v["secretRecord"]["record"]["name"].as_str().unwrap();
    snap.insert(format!("s.{name}"), v["secretRecord"]["record"].clone());
    let snap = serde_json::to_string(&Value::Object(snap)).unwrap();

    let vault = owner_vault(&v, &snap);
    let bytes = vault.get_secret(name).expect("open the JS-sealed secret");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        v["secretSealed"]["expectOpenPlaintext"].as_str().unwrap(),
        "the wasm vault must open the JS-sealed secret to the same plaintext"
    );
}

#[test]
fn wasm_recover_rederives_the_same_master_and_reads() {
    // From the OWNER key alone (no snapshot), recover() must re-derive the deterministic master and
    // re-enroll — then a secret put under it survives a snapshot roundtrip. This pins deriveOwnerMaster
    // parity through the wasm path (the recovered master must equal the JS-derived one to open the
    // JS secret, which the previous test already covers; here we prove recover() is self-consistent).
    let v = vectors();
    let owner_json = serde_json::to_string(&v["owner"]).unwrap();
    let ns = v["ns"].as_str().unwrap();

    let vault = WasmVault::new(&owner_json, ns, "2026-06-26T00:00:00.000Z").unwrap();
    assert!(!vault.is_enrolled().unwrap());
    vault.recover("owner").unwrap();
    assert!(vault.is_enrolled().unwrap());

    // The recovered master must equal the JS-derived one: seed the JS sealed secret and open it.
    let mut snap: Map<String, Value> = serde_json::from_str(&vault.snapshot().unwrap()).unwrap();
    let name = v["secretRecord"]["record"]["name"].as_str().unwrap();
    snap.insert(format!("s.{name}"), v["secretRecord"]["record"].clone());
    vault
        .load_snapshot(&serde_json::to_string(&Value::Object(snap)).unwrap())
        .unwrap();
    let bytes = vault.get_secret(name).unwrap();
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        v["secretSealed"]["expectOpenPlaintext"].as_str().unwrap(),
        "recover() must re-derive the byte-identical JS owner master"
    );
}
