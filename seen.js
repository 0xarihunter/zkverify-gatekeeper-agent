// Persisted seen-set of proof_tx values, used to detect PROOF_REUSED.
// Stored as a JSON array on disk so reuse is detected across restarts.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const SEEN_FILE = process.env.SEEN_FILE || path.join(here, "seen-proof-tx.json");

let seen = new Set();
try {
  const arr = JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"));
  if (Array.isArray(arr)) seen = new Set(arr.map((x) => String(x).toLowerCase()));
} catch {
  seen = new Set(); // first run: file does not exist yet
}

export function hasSeen(proofTx) {
  return typeof proofTx === "string" && seen.has(proofTx.toLowerCase());
}

export function markSeen(proofTx) {
  if (typeof proofTx !== "string" || proofTx.length === 0) return;
  const key = proofTx.toLowerCase();
  if (seen.has(key)) return;
  seen.add(key);
  const tmp = SEEN_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify([...seen], null, 2));
  fs.renameSync(tmp, SEEN_FILE);
}

export function seenCount() {
  return seen.size;
}
