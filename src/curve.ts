/** Variable-time Cheetah arithmetic for trusted offline tools. */
import {
  PRIME,
  NockchainError,
  bigintBytes,
  bytesBigint,
  concatBytes,
} from "./core.js";

type Field = readonly bigint[];
export const ORDER =
  0x7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accfn;
const ZERO: Field = Object.freeze([0n, 0n, 0n, 0n, 0n, 0n]);
const ONE: Field = Object.freeze([1n, 0n, 0n, 0n, 0n, 0n]);
const INVERSE_EXPONENT = PRIME ** 6n - 2n;
function equal(a: Field, b: Field): boolean {
  return a.every((x, i) => x === b[i]);
}
function add(a: Field, b: Field): Field {
  return a.map((x, i) => (x + b[i]) % PRIME);
}
function sub(a: Field, b: Field): Field {
  return a.map((x, i) => (x - b[i] + PRIME) % PRIME);
}
function scale(a: Field, value: bigint): Field {
  return a.map((x) => (x * value) % PRIME);
}
function mul(a: Field, b: Field): Field {
  const result = Array<bigint>(11).fill(0n);
  for (let i = 0; i < 6; i++)
    for (let j = 0; j < 6; j++) result[i + j] += a[i] * b[j];
  for (let i = 6; i < 11; i++) result[i - 6] += 7n * result[i];
  return result.slice(0, 6).map((x) => x % PRIME);
}
function square(a: Field): Field {
  return mul(a, a);
}
function inverse(a: Field): Field {
  let result = ONE;
  for (const bit of INVERSE_EXPONENT.toString(2)) {
    result = square(result);
    if (bit === "1") result = mul(result, a);
  }
  return result;
}
export class Point {
  readonly x: Field;
  readonly y: Field;
  readonly z: Field;
  constructor(x: Field = ZERO, y: Field = ZERO, z: Field = ZERO) {
    this.x = Object.freeze([...x]);
    this.y = Object.freeze([...y]);
    this.z = Object.freeze([...z]);
    Object.freeze(this);
  }
  get infinity(): boolean {
    return equal(this.z, ZERO);
  }
  double(): Point {
    if (this.infinity || equal(this.y, ZERO)) return new Point();
    const a = square(this.x),
      b = square(this.y),
      c = square(b);
    const d = scale(sub(sub(square(add(this.x, b)), a), c), 2n);
    const e = add(scale(a, 3n), square(square(this.z)));
    const x = sub(square(e), scale(d, 2n));
    return new Point(
      x,
      sub(mul(e, sub(d, x)), scale(c, 8n)),
      scale(mul(this.y, this.z), 2n),
    );
  }
  plus(q: Point): Point {
    if (this.infinity) return q;
    if (q.infinity) return this;
    const z1 = square(this.z),
      z2 = square(q.z);
    const u1 = mul(this.x, z2),
      u2 = mul(q.x, z1);
    const s1 = mul(mul(this.y, q.z), z2),
      s2 = mul(mul(q.y, this.z), z1);
    if (equal(u1, u2)) return equal(s1, s2) ? this.double() : new Point();
    const h = sub(u2, u1),
      i = square(scale(h, 2n)),
      j = mul(h, i);
    const r = scale(sub(s2, s1), 2n),
      v = mul(u1, i);
    const x = sub(sub(square(r), j), scale(v, 2n));
    const y = sub(mul(r, sub(v, x)), scale(mul(s1, j), 2n));
    const z = mul(sub(sub(square(add(this.z, q.z)), z1), z2), h);
    return new Point(x, y, z);
  }
  times(value: bigint): Point {
    let result = new Point();
    for (const bit of value.toString(2)) {
      result = result.double();
      if (bit === "1") result = result.plus(this);
    }
    return result;
  }
  affine(): Point {
    if (this.infinity || equal(this.z, ONE)) return this;
    const z = inverse(this.z),
      z2 = square(z);
    return new Point(mul(this.x, z2), mul(mul(this.y, z2), z), ONE);
  }
  toBytes(): Uint8Array {
    const p = this.affine();
    return concatBytes(
      new Uint8Array([1]),
      ...[...p.y]
        .reverse()
        .concat([...p.x].reverse())
        .map((x) => bigintBytes(x, 8)),
    );
  }
}
export const GENERATOR = new Point(
  [
    2754611494552410273n,
    8599518745794843693n,
    10526511002404673680n,
    4830863958577994148n,
    375185138577093320n,
    12938930721685970739n,
  ],
  [
    15384029202802550068n,
    2774812795997841935n,
    14375303400746062753n,
    10708493419890101954n,
    13187678623570541764n,
    9990732138772505951n,
  ],
  ONE,
);
export function parsePoint(data: Uint8Array): Point {
  if (!(data instanceof Uint8Array) || data.length !== 97 || data[0] !== 1)
    throw new NockchainError("Invalid Cheetah public key");
  const y: bigint[] = [],
    x: bigint[] = [];
  for (let i = 1; i < 49; i += 8)
    y.unshift(bytesBigint(data.subarray(i, i + 8)));
  for (let i = 49; i < 97; i += 8)
    x.unshift(bytesBigint(data.subarray(i, i + 8)));
  if ([...x, ...y].some((value) => value >= PRIME))
    throw new NockchainError("Noncanonical Cheetah coordinate");
  const p = new Point(x, y, ONE);
  if (
    !equal(
      square(y),
      add(add(mul(square(x), x), x), [395n, 1n, 0n, 0n, 0n, 0n]),
    ) ||
    !p.times(ORDER).infinity
  )
    throw new NockchainError("Cheetah point outside prime-order subgroup");
  return p;
}
