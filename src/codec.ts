import {
  Cell,
  MAX_JAM_BYTES,
  MAX_NOUN_NODES,
  NockchainError,
  atom,
} from "./core.js";
import type { Noun } from "./core.js";

/** Literal LSB-first jam with bounded logical expansion, matching the Rust corpus. */
export function jam(noun: Noun): Uint8Array {
  const data: number[] = [];
  let bit = 0;
  const write = (value: bigint, size: number): void => {
    for (let i = 0; i < size; i++) {
      if (Math.floor(bit / 8) === data.length) data.push(0);
      data[Math.floor(bit / 8)] |=
        Number((value >> BigInt(i)) & 1n) << (bit % 8);
      bit++;
    }
  };
  const stack: Noun[] = [noun];
  let nodes = 0;
  while (stack.length) {
    const current = stack.pop()!;
    if (++nodes > MAX_NOUN_NODES)
      throw new NockchainError("Noun exceeds logical node limit");
    if (current instanceof Cell) {
      write(1n, 2);
      stack.push(current.tail, current.head);
    } else {
      const value = atom(current);
      write(0n, 1);
      if (value === 0n) write(1n, 1);
      else {
        const length = value.toString(2).length,
          size = length.toString(2).length;
        write(0n, size);
        write(1n, 1);
        write(BigInt(length), size - 1);
        write(value, length);
      }
    }
    if (data.length > MAX_JAM_BYTES)
      throw new NockchainError("Jam exceeds byte limit");
  }
  return Uint8Array.from(data);
}
/** Reject forward/cyclic references, field overflow, excess data and expansion bombs. */
export function cue(data: Uint8Array): Noun {
  if (
    !(data instanceof Uint8Array) ||
    !data.length ||
    data.length > MAX_JAM_BYTES
  )
    throw new NockchainError("Invalid jam size");
  let bit = 0;
  const read = (size: number): bigint => {
    if (size < 0 || size > 64 || size > data.length * 8 - bit)
      throw new NockchainError("Truncated or oversized jam atom");
    let result = 0n;
    for (let i = 0; i < size; i++, bit++)
      result |=
        BigInt((data[Math.floor(bit / 8)] >> (bit % 8)) & 1) << BigInt(i);
    return result;
  };
  const rub = (): bigint => {
    let size = 0;
    while (read(1) === 0n)
      if (++size > 7) throw new NockchainError("Jam atom exceeds field width");
    return size === 0 ? 0n : read(Number(read(size - 1)) + 2 ** (size - 1));
  };
  type Saved = { noun: Noun; nodes: number };
  const refs = new Map<number, Saved>();
  const stack: { start: number; head?: Saved }[] = [];
  let current: Saved;
  for (;;) {
    const start = bit;
    if (read(1) === 0n) {
      current = { noun: atom(rub()), nodes: 1 };
      refs.set(start, current);
    } else if (read(1) === 0n) {
      if (stack.length >= MAX_NOUN_NODES)
        throw new NockchainError("Jam exceeds node limit");
      stack.push({ start });
      continue;
    } else {
      const position = rub();
      const saved =
        position < BigInt(start) ? refs.get(Number(position)) : undefined;
      if (!saved)
        throw new NockchainError("Invalid or cyclic jam backreference");
      current = saved;
    }
    while (stack.length) {
      const frame = stack[stack.length - 1];
      if (!frame.head) {
        frame.head = current;
        break;
      }
      const nodes = 1 + frame.head.nodes + current.nodes;
      if (nodes > MAX_NOUN_NODES)
        throw new NockchainError("Jam exceeds logical node limit");
      current = { noun: new Cell(frame.head.noun, current.noun), nodes };
      refs.set(frame.start, current);
      stack.pop();
    }
    if (!stack.length) break;
  }
  if (data.length * 8 - bit > 7 || read(data.length * 8 - bit) !== 0n)
    throw new NockchainError("Trailing jam data");
  return current.noun;
}
