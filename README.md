# ce-iam-core-wasm

The wasm-bindgen port of [`ce-iam-core`](../ce-iam/crates/ce-iam-core) — the **small** half of CE IAM
("basic auth") — for the browser. It exposes two things to JavaScript, over the SAME Rust code the
native `ce-iam` CLI runs, so the browser, the CLI, and the `ce-secrets` JS reference all agree
byte-for-byte (golden-vectored against `ce-secrets/src/crypto.mjs`):

- **The secrets vault** (`WasmVault`) — `init` / `recover` / `getSecret` / `putSecret` / `listSecrets`
  / device pairing (`requestPairing` / `approvePairing` / `listDevices`) / `issueGrant` / `verifyGrant`
  / `signChallenge` / `verifyAuth`. Owner-derived master, ECIES-wrapped per device, AES-256-GCM-sealed
  secrets.
- **Capability VERIFY** (`verify`) — runs `ce_cap::authorize` over a presented capability chain.
  VERIFY only; minting authority lives in the big `ce-iam` crate and never enters the browser.

It is the wasm layer under [`ce-iam-ts`](../ce-iam-ts), the TS SDK that ce-cast (and any browser tab)
uses instead of vendoring `crypto.mjs` / `vault.mjs`.

## Wasm-clean

The dependency graph is pure crypto/serde — `ce-iam-core` + `ce-secrets-rs` + `ce-cap` + `ce-identity`
+ `serde`/`serde_json`/`hex`/`wasm-bindgen`. No tokio, no reqwest, no libp2p, no `ce-rs`. The two host
hooks the browser provides:

- **OS RNG** → `getrandom`'s `js` backend (Web Crypto / Node crypto), enabled by the `getrandom`
  feature here. Used for device-key / ephemeral-ECDH / IV / grant-id / pairing-code entropy.
- **Wall clock** → injected from JS (`new Date().toISOString()`) into the vault's record clock, so wasm
  never reaches `SystemTime` (which traps under wasm).

## The store split (why the vault is snapshot-driven)

The vault is generic over an async `Store`. In the browser the durable store is the **mesh KV**
(cast-control's `ce-kv/<ns>/1` service) reached over the local CE node — that lives in **TypeScript**.
So this port does NOT marshal an async JS store across the wasm boundary. Instead the TS SDK:

1. loads the namespace's entries off the mesh KV and hands wasm a JSON snapshot (`loadSnapshot`),
2. runs the op in wasm over an in-memory store (always Ready, so a trivial poll-once executor drives
   the async vault with no runtime),
3. reads the mutated snapshot back (`snapshot`) and persists the diff to the mesh KV.

All crypto + vault orchestration stays in Rust (one implementation); only transport/persistence is TS.

## Layout

- `src/core.rs` — the pure (non-wasm-bindgen) implementation. Host-testable; the golden vectors run
  against this exact code path.
- `src/lib.rs` — the thin `#[wasm_bindgen]` wrappers that delegate to `core` and map errors to thrown
  `JsValue` strings.
- `tests/golden_wasm.rs` — golden-vector gate: drives the JS-produced `secrets_vectors.json` records
  through the wasm code path (verify the JS challenge + grant, open the JS-sealed secret, re-derive the
  owner master). Same fixtures as `ce-iam-core`'s golden test.

## Build

```bash
# host tests (CI / ce-build) — the wasm exports compile for the host via the rlib crate-type
cargo test                       # or: tools/ce-build ce-iam-core-wasm test   (on the relay)

# the browser bundle (emits ../ce-iam-ts/src/wasm/)
rustup target add wasm32-unknown-unknown    # once
wasm-pack build --target web --release --out-dir ../ce-iam-ts/src/wasm
```
