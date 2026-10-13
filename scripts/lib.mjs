import { buildPoseidon } from "circomlibjs";

export const DEPTH = 20;
export const MAX_SKILLS = 64;

export async function poseidonTools() {
  const poseidon = await buildPoseidon();
  const H = (values) => poseidon.F.toObject(poseidon(values));
  return { poseidon, H };
}

export function merkle(H, leaves, depth, index) {
  let level = leaves.slice();
  const size = 2 ** depth;
  while (level.length < size) level.push(0n);
  const pathElements = [];
  const pathIndices = [];
  let cursor = index;
  for (let d = 0; d < depth; d++) {
    pathElements.push(level[cursor % 2 === 0 ? cursor + 1 : cursor - 1].toString());
    pathIndices.push(cursor % 2);
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(H([level[i], level[i + 1]]));
    level = next;
    cursor = Math.floor(cursor / 2);
  }
  return { root: level[0].toString(), pathElements, pathIndices };
}

let cachedInput;

async function buildValidInput() {
  const { H } = await poseidonTools();
  const secret = 424242424242n;
  const issuerId = 7n;
  const scopeBitmap = (1n << 0n) | (1n << 3n) | (1n << 9n);
  const leaf = H([secret, issuerId, scopeBitmap]);
  const leaves = [H([1n, 1n, 1n]), leaf, H([2n, 2n, 2n]), H([3n, 3n, 3n])];
  const path = merkle(H, leaves, DEPTH, 1);
  return {
    secret: secret.toString(), issuerId: issuerId.toString(),
    scopeBitmap: scopeBitmap.toString(),
    pathElements: path.pathElements, pathIndices: path.pathIndices,
    issuerRoot: path.root, skillIndex: "3",
    sessionScope: "987654321", requestBinding: "123456789",
  };
}

export async function validInput(overrides = {}) {
  cachedInput ??= buildValidInput();
  return { ...structuredClone(await cachedInput), ...overrides };
}
