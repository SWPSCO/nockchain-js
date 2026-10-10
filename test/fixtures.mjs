import { readFileSync } from "node:fs";
import * as n from "../dist/index.js";

// JSON number source text preserves field values beyond Number.MAX_SAFE_INTEGER.
export const load = (name) =>
  JSON.parse(
    readFileSync(new URL(`../testdata/${name}`, import.meta.url), "utf8"),
    (_key, value, context) =>
      typeof value === "number" ? BigInt(context.source) : value,
  );
export const reference = load("reference.json");
export const consensus = load("consensus.json");
export const oracle = new Map(
  consensus.transactions.map((value) => [value.id, value]),
);
export const fromHex = (value) => Uint8Array.from(Buffer.from(value, "hex"));
export const hex = (value) => Buffer.from(value).toString("hex");
const keys = new Map();
export function keyFor(seed, path = []) {
  const identity = `${seed}/${path.join("/")}`;
  if (!keys.has(identity)) {
    let key = n.master(fromHex(seed));
    for (const index of path) key = key.child(Number(index));
    keys.set(identity, key);
  }
  return keys.get(identity);
}
export function makeNoun(value) {
  return Array.isArray(value)
    ? new n.Cell(makeNoun(value[0]), makeNoun(value[1]))
    : n.atom(value);
}
export function noteFrom(value) {
  return new n.NoteV1({
    originPage: value.originPage,
    name: new n.NoteName(n.digest(value.name.first), n.digest(value.name.last)),
    noteData: 0n,
    nicks: value.nicks,
  });
}
export function lockFrom(value) {
  return new n.LockV1(
    2,
    value.keys.map(n.digest),
    value.timed
      ? { relative: { min: 5n, max: 50n }, absolute: { min: 100n, max: 200n } }
      : null,
  );
}
