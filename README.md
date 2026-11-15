# zkVerify Gatekeeper Agent — "Bansur Gatekeeper"

A Proof Gatekeeper agent for the **zkVerify Agent Games** (Season 01),
competing under the handle **arihunter**.

The agent receives signed payment-approval tasks from the Agent Games
platform, decides APPROVE / REJECT with a deterministic checklist, and
answers with a locally generated Groth16 proof. The official gatekeeper
circuit enforces the decision itself: a proof for a wrong decision
cannot be generated (witness generation assert-fails), so the agent
cryptographically cannot lie about a verdict.

## How it works

- `POST /agent` — HMAC-SHA256 verified over the raw body before parsing;
  every response is signed the same way. Handles the platform preflight
  handshake (`agent-games.preflight.v1`).
- `GET /health` — liveness check.
- Decision order: PROOF_REUSED → VK_SUBSTITUTION → THRESHOLD_MISMATCH →
  EXPIRED_CONDITION → RECIPIENT_MISMATCH → AMOUNT_OVERFLOW → APPROVE.
  Boundary semantics were probed from the circuit itself: balance equal
  to the minimum is valid, amount equal to the cap is valid, and
  `current_block == expiry_block` is already expired.
- Proofs are generated locally with snarkjs against the official
  `gatekeeper` circuit (Groth16 / BN254) in ~0.3–1 s per task, far
  inside the platform's 60-second deadline.
- The seen-set of proof references is persisted to disk so a restart
  cannot make the agent accept a replayed proof.
- Fail closed: any internal error produces a signed REJECT.

## Local test results

11/11 checks pass in the local harness (signed envelope replays):
preflight, valid approval, all six trap types including both expiry
boundaries, proof-reuse on a duplicate reference, and the
bad-signature path. Every attached proof verifies locally against the
exported verification key.

## Run

```sh
npm install
AGENT_GAMES_HMAC_SECRET=<platform secret> npm start   # PORT env, default 8787
```

## Files

- `server.js` — HTTP service (Node stdlib only).
- `proof.js` — circuit input encoding + snarkjs proving wrapper.
- `seen.js` — persisted proof-reference seen-set.
- `circuits/` — official gatekeeper artifacts (wasm, zkey, vkey).

Built for the Agent Games Proof Gatekeeper track. #AgentGames
