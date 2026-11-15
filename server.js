// Proof Gatekeeper agent — zkVerify Agent Games.
//
// POST /agent accepts signed envelopes from the platform:
//   - HMAC-SHA256 (hex) over the RAW request body in header `x-agent-games-signature`,
//     verified BEFORE parsing. Secret from env AGENT_GAMES_HMAC_SECRET.
//   - type "agent-games.preflight.v1"       -> { ok: true, protocolVersion: "v1" }
//   - type "agent-games.proof-gatekeeper.v1" -> deterministic decision + Groth16 proof
// EVERY response is signed the same way over its exact raw body.
// Fail closed: any internal error -> REJECT / INTERNAL_ERROR, signed, never a hang.
//
// Local-only build for the Agent Games registration phase; no outbound calls.

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildCircuitInput, generateProof } from "./proof.js";
import { hasSeen, markSeen } from "./seen.js";

const here = path.dirname(fileURLToPath(import.meta.url));

// Minimal .env loader (no dependency): values in the real environment win.
try {
  for (const line of fs.readFileSync(path.join(here, ".env"), "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch { /* no .env file — rely on real env */ }

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
if (!SECRET) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set (env or agent/.env). Refusing to start.");
  process.exit(1);
}
const PORT = Number(process.env.PORT || 8787);
const PROOF_SOFT_TIMEOUT_MS = 50_000;

function hmacHex(raw) {
  return crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
}

function signatureValid(rawBody, headerValue) {
  if (typeof headerValue !== "string") return false;
  const expected = Buffer.from(hmacHex(rawBody), "utf8");
  const given = Buffer.from(headerValue.trim().toLowerCase(), "utf8");
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

function sendSigned(res, status, obj) {
  const raw = Buffer.from(JSON.stringify(obj), "utf8");
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(raw),
  });
  res.end(raw);
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("proof generation soft timeout")), ms)),
  ]);
}

// Deterministic decision, in the exact order required by the task spec.
// Returns { decision, reason_code } — proof handling is the caller's job.
function decide(input) {
  if (hasSeen(input.proof_tx)) return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  if (String(input.proof_vk).toLowerCase() !== String(input.registered_vk).toLowerCase())
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  if (BigInt(input.public_balance) < BigInt(input.minimum))
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  // Boundary semantics CONFIRMED against the circuit (agent/probe-boundary.mjs):
  // balance == minimum is VALID, amount == maxTransfer is VALID,
  // but current_block == expiry_block is already EXPIRED (decision=APPROVE assert-fails).
  if (BigInt(input.current_block) >= BigInt(input.expiry_block))
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase())
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  if (BigInt(input.amount) > BigInt(input.max_transfer))
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

async function handleGatekeeper(res, envelope) {
  const input = envelope.input || {};
  const proofTx = typeof input.proof_tx === "string" ? input.proof_tx : null;
  let decision, reason_code;
  try {
    ({ decision, reason_code } = decide(input));
  } catch {
    return sendSigned(res, 200, { decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: proofTx, proof: null, public_signals: null });
  }

  let proof = null, publicSignals = null;
  if (reason_code !== "PROOF_REUSED") {
    // Every non-reused task must carry a proof — including REJECTs of traps.
    try {
      const circuitInput = buildCircuitInput(input, decision, envelope.task_id);
      ({ proof, publicSignals } = await withTimeout(generateProof(circuitInput), PROOF_SOFT_TIMEOUT_MS));
    } catch (err) {
      console.error("proof generation failed:", err.message);
      markSeen(proofTx);
      return sendSigned(res, 200, { decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: proofTx, proof: null, public_signals: null });
    }
  }
  markSeen(proofTx); // after processing, whatever the decision was
  return sendSigned(res, 200, { decision, reason_code, proof_tx: proofTx, proof, public_signals: publicSignals });
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ok: true }));
  }
  if (req.method !== "POST" || req.url !== "/agent") {
    return sendSigned(res, 404, { error: "not_found" });
  }
  const chunks = [];
  let size = 0;
  req.on("data", (c) => {
    size += c.length;
    if (size > 1_000_000) { req.destroy(); return; }
    chunks.push(c);
  });
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    // 1. Verify HMAC over the RAW body before parsing anything.
    if (!signatureValid(raw, req.headers["x-agent-games-signature"])) {
      return sendSigned(res, 401, { error: "invalid_signature" });
    }
    // 2. Parse.
    let envelope;
    try { envelope = JSON.parse(raw.toString("utf8")); }
    catch { return sendSigned(res, 400, { error: "invalid_json" }); }
    // 3. Dispatch.
    try {
      if (envelope.type === "agent-games.preflight.v1") {
        return sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
      }
      if (envelope.type === "agent-games.proof-gatekeeper.v1") {
        return await handleGatekeeper(res, envelope);
      }
      return sendSigned(res, 400, { error: "unknown_type" });
    } catch (err) {
      console.error("handler error:", err);
      return sendSigned(res, 200, { decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: null, proof: null, public_signals: null });
    }
  });
});

server.listen(PORT, () => {
  console.log(`gatekeeper agent listening on :${PORT} (POST /agent, GET /health)`);
});
