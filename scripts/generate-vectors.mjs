import { mkdir, writeFile } from "node:fs/promises";
import { poseidonTools, validInput } from "./lib.mjs";

const input = await validInput();
const { H } = await poseidonTools();
const expected = {
  publicSignals: [
    H([BigInt(input.secret), BigInt(input.sessionScope)]).toString(),
    H([BigInt(input.secret), BigInt(input.requestBinding)]).toString(),
    input.issuerRoot, input.skillIndex, input.sessionScope, input.requestBinding,
  ],
};
await mkdir("test-vectors", { recursive: true });
await writeFile("test-vectors/credential-v2-input.json", JSON.stringify(input, null, 2) + "\n");
await writeFile("test-vectors/credential-v2-expected.json", JSON.stringify(expected, null, 2) + "\n");
console.log("wrote deterministic credential-v2 vectors");
