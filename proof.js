// Proof generation for the Proof Gatekeeper circuit (gatekeeper.wasm / gatekeeper_final.zkey).
//
// Circuit inputs CONFIRMED by probing the wasm (see ../BUILD-REPORT.md and ../probe-inputs.mjs):
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
//   recipient, conditionRecipient, amount, maxTransfer, decision, taskId  (all public, size 1)
//   salt (private, size 1)
// The circuit itself enforces that `decision` matches its own evaluation of the
// other fields: a wrong decision makes witness generation Assert-Fail, so no
// proof can be produced for a decision our checklist did not reach.

import * as snarkjs from "snarkjs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
let keccak256;
try {
  ({ keccak256 } = require("js-sha3")); // present in the installed snarkjs dependency tree
} catch {
  const { createHash } = require("node:crypto");
  keccak256 = (s) => createHash("sha256").update(s).digest("hex"); // fallback only; see README
}

const here = path.dirname(fileURLToPath(import.meta.url));
import fs from "node:fs";
const defaultCircuits = fs.existsSync(path.join(here, "..", "circuits", "gatekeeper.wasm"))
  ? path.join(here, "..", "circuits")
  : path.join(here, "circuits");
export const CIRCUITS_DIR = process.env.CIRCUITS_DIR || defaultCircuits;
const WASM = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");

export const SALT = process.env.AGENT_GAMES_SALT || "123456789";

// Hex string (with or without 0x) -> field element as decimal string.
// snarkjs normalizes mod the BN254 prime, so full 256-bit hashes are fine.
export function hexToField(hex) {
  if (typeof hex !== "string" || !/^(0x)?[0-9a-fA-F]+$/.test(hex.trim())) {
    throw new Error(`invalid hex value: ${hex}`);
  }
  return BigInt(hex.trim().toLowerCase().startsWith("0x") ? hex.trim() : "0x" + hex.trim()).toString();
}

export function taskIdToField(taskId) {
  return BigInt("0x" + keccak256(String(taskId))).toString();
}

// Build the circuit input object from a gatekeeper envelope `input` + our decision.
export function buildCircuitInput(input, decision /* "APPROVE" | "REJECT" */, taskId) {
  return {
    registeredVkHash: hexToField(input.registered_vk),
    proofVkHash: hexToField(input.proof_vk),
    minimum: BigInt(input.minimum).toString(),
    publicBalance: BigInt(input.public_balance).toString(),
    expiryBlock: BigInt(input.expiry_block).toString(),
    currentBlock: BigInt(input.current_block).toString(),
    recipient: hexToField(input.recipient),
    conditionRecipient: hexToField(input.condition_recipient),
    amount: BigInt(input.amount).toString(),
    maxTransfer: BigInt(input.max_transfer).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: taskIdToField(taskId),
    salt: SALT,
  };
}

// Generate a Groth16 proof. Returns { proof, publicSignals } (snarkjs objects).
export async function generateProof(circuitInput) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}
