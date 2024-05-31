import { buildPoseidon } from "circomlibjs";
import { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim";

import { generate_input } from "../prover";
import { bigIntToChunkedBytes, bytesToBigInt } from "@zk-email/helpers";
const path = require("path");
const fs = require("fs");
const wasm_tester = require("circom_tester").wasm;

describe("Twitter email test", function () {
  jest.setTimeout(10 * 60 * 1000); // 10 minutes

  let rawEmail: Buffer;
  let circuit: any;

  beforeAll(async () => {
    rawEmail = fs.readFileSync(
      path.join(__dirname, "../emls/wise.eml"),
      "utf8"
    );
    circuit = await wasm_tester(path.join(__dirname, "../wise_send.circom"), {
      // NOTE: We are running tests against pre-compiled circuit in the below path
      // You need to manually compile when changes are made to circuit if `recompile` is set to `false`.
      recompile: false,
      output: path.join(__dirname, "../build"),
      include: [path.join(__dirname, "../node_modules")],
    });
  });

  it("should verify twitter email", async function () {
    const twitterVerifierInputs = await generate_input(rawEmail);
    console.log(twitterVerifierInputs);
    const witness = await circuit.calculateWitness(twitterVerifierInputs);
    await circuit.checkConstraints(witness);
    console.log(witness);
    // Calculate DKIM pubkey hash to verify its same as the one from circuit output
    // We input pubkey as 121 * 17 chunk, but the circuit convert it to 242 * 9 chunk for hashing
    // https://zkrepl.dev/?gist=43ce7dce2466c63812f6efec5b13aa73 - This can be used to get pubkey hash from 121 * 17 chunk
    const dkimResult = await verifyDKIMSignature(rawEmail, "wise.com");
    const poseidon = await buildPoseidon();
    const pubkeyChunked = bigIntToChunkedBytes(dkimResult.publicKey, 242, 9);
    const hash = poseidon(pubkeyChunked);
    // console.log(witness);
    // Assert pubkey hash
    expect(witness[1]).toEqual(poseidon.F.toObject(hash));
    // // Verify the username is correctly extracted and packed form email body
    const fromEmailBytes = new TextEncoder()
      .encode("noreply@wise.com")
      .reverse(); // Circuit pack in reverse order
    console.log(witness[2], bytesToBigInt(fromEmailBytes));
    expect(witness[2]).toEqual(bytesToBigInt(fromEmailBytes));

    const timestampBytes = new TextEncoder().encode("1716487535").reverse(); // Circuit pack in reverse order
    console.log(witness[3], bytesToBigInt(timestampBytes));
    expect(witness[3]).toEqual(bytesToBigInt(timestampBytes));
    // // Check address public input
    // expect(witness[3]).toEqual(BigInt(ethAddress));
  });

  //   it("should fail if the twitterUsernameIndex is invalid", async function () {
  //     const twitterVerifierInputs = await generateTwitterVerifierCircuitInputs(
  //       rawEmail,
  //       ethAddress
  //     );
  //     twitterVerifierInputs.twitterUsernameIndex = (
  //       Number((await twitterVerifierInputs).twitterUsernameIndex) + 1
  //     ).toString();

  //     expect.assertions(1);
  //     try {
  //       const witness = await circuit.calculateWitness(twitterVerifierInputs);
  //       await circuit.checkConstraints(witness);
  //     } catch (error) {
  //       expect((error as Error).message).toMatch("Assert Failed");
  //     }
  //   });
});
