import * as snarkjs from "snarkjs";
import { createWriteStream, readFileSync, writeFile } from "fs";
import fs from "fs";
import {
  Uint8ArrayToCharArray,
  Uint8ArrayToString,
  assert,
  bufferToString,
  bytesToBigInt,
  int8toBytes,
  mergeUInt8Arrays,
  stringToBytes,
  toCircomBigIntBytes,
  partialSha,
  sha256Pad,
  shaHash,
  generateEmailVerifierInputs,
} from "@zk-email/helpers";
import {
  CIRCOM_FIELD_MODULUS,
  MAX_BODY_PADDED_BYTES,
  MAX_HEADER_PADDED_BYTES,
} from "@zk-email/helpers";
import { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim";
import nf from "node-forge";
export const STRING_PRESELECTOR = `#454745;"> Hello `;
const pki = nf.pki.publicKeyFromPem;
import { Writable } from "stream";

enum Compress {
  None, // Extend this enum based on the compression options you need
}

class SerializationError extends Error {}

interface Serializable {
  data: number;
}
export interface ICircuitInputs {
  modulus?: string[];
  signature?: string[];
  base_message?: string[];
  in_padded?: string[];
  in_body_padded?: string[];
  in_body_len_padded_bytes?: string;
  in_padded_n_bytes?: string[];
  in_len_padded_bytes?: string;
  in_body_hash?: string[];
  precomputed_sha?: string[];
  body_hash_idx?: string;
  email_from_idx?: string | number;
  email_to_idx?: string | number;
  email_timestamp_idx?: string;

  email_date_idx?: string;
  intent_hash?: string;

  wise_amount_idx?: string;
  reference_code_idx?: string;

  // subject commands only
  command_idx?: string;
  message_id_idx?: string;
  amount_idx?: string;
  currency_idx?: string;
  recipient_idx?: string;
  custom_message_id_from?: string[];
  custom_message_id_recipient?: string[];
  nullifier?: string;
  relayer?: string;
}

export enum CircuitType {
  RSA = "rsa",
  SHA = "sha",
  TEST = "test",
  EMAIL_VENMO_SEND = "venmo_send",
  EMAIL_VENMO_REGISTRATION = "venmo_registration",
  EMAIL_HDFC_SEND = "hdfc_send",
  EMAIL_HDFC_REGISTRATION = "hdfc_registration",
  EMAIL_PAYLAH_SEND = "paylah_send",
  EMAIL_PAYLAH_REGISTRATION = "paylah_registration",
  EMAIL_WISE_SEND = "wise_send",
}

async function findSelector(
  a: Uint8Array,
  selector: number[]
): Promise<number> {
  let i = 0;
  let j = 0;
  while (i < a.length) {
    if (a[i] === selector[j]) {
      j++;
      if (j === selector.length) {
        return i - j + 1;
      }
    } else {
      j = 0;
    }
    i++;
  }
  return -1;
}

// Returns the part of str that appears after substr
function trimStrByStr(str: string, substr: string) {
  const index = str.indexOf(substr);
  if (index === -1) return str;
  return str.slice(index + substr.length, str.length);
}

function strToCharArrayStr(str: string) {
  return str.split("").map((char) => char.charCodeAt(0).toString());
}

// padWithZero(bodyRemaining, MAX_BODY_PADDED_BYTES)
function padWithZero(arr: Uint8Array, length: number) {
  while (arr.length < length) {
    arr = mergeUInt8Arrays(arr, int8toBytes(0));
  }
  return arr;
}

async function getCircuitInputs(
  rsa_signature: BigInt,
  rsa_modulus: BigInt,
  message: Buffer,
  body: Buffer,
  body_hash: string,
  intent_hash: string,
  circuit: CircuitType
): Promise<{
  valid: {
    validSignatureFormat?: boolean;
    validMessage?: boolean;
  };
  circuitInputs: ICircuitInputs;
}> {
  //console.log("Starting processing of inputs");

  let MAX_BODY_PADDED_BYTES_FOR_EMAIL_TYPE = 30312;
  let STRING_PRESELECTOR_FOR_EMAIL_TYPE = STRING_PRESELECTOR;

  // Derive modulus from signature
  // const modulusBigInt = bytesToBigInt(pubKeyParts[2]);
  const modulusBigInt = rsa_modulus;
  // Message is the email header with the body hash
  const prehash_message_string = message;
  // const baseMessageBigInt = AAYUSH_PREHASH_MESSAGE_INT; // bytesToBigInt(stringToBytes(message)) ||
  // const postShaBigint = AAYUSH_POSTHASH_MESSAGE_PADDED_INT;
  const signatureBigInt = rsa_signature;

  // Perform conversions
  const prehashBytesUnpadded =
    typeof prehash_message_string == "string"
      ? new TextEncoder().encode(prehash_message_string)
      : Uint8Array.from(prehash_message_string);
  const postShaBigintUnpadded =
    bytesToBigInt(
      stringToBytes((await shaHash(prehashBytesUnpadded)).toString())
    ) % CIRCOM_FIELD_MODULUS;

  // Sha add padding
  // 65 comes from the 64 at the end and the 1 bit in the start, then 63 comes from the formula to round it up to the nearest 64. see sha256algorithm.com for a more full explanation of paddnig length
  const calc_length = Math.floor((body.length + 63 + 65) / 64) * 64;
  const [messagePadded, messagePaddedLen] = await sha256Pad(
    prehashBytesUnpadded,
    MAX_HEADER_PADDED_BYTES
  );
  const [bodyPadded, bodyPaddedLen] = await sha256Pad(
    body,
    Math.max(MAX_BODY_PADDED_BYTES_FOR_EMAIL_TYPE, calc_length)
  );

  // Convet messagePadded to string to print the specific header data that is signed
  // //console.log(JSON.stringify(message).toString());

  // Ensure SHA manual unpadded is running the correct function
  const shaOut = await partialSha(messagePadded, messagePaddedLen);

  assert(
    (await Uint8ArrayToString(shaOut)) ===
      (await Uint8ArrayToString(
        Uint8Array.from(await shaHash(prehashBytesUnpadded))
      )),
    "SHA256 calculation did not match!"
  );

  // Precompute SHA prefix
  const selector = STRING_PRESELECTOR_FOR_EMAIL_TYPE.split("").map((char) =>
    char.charCodeAt(0)
  );
  const selector_loc = await findSelector(bodyPadded, selector);
  //console.log("Body selector found at: ", selector_loc);
  let shaCutoffIndex =
    Math.floor((await findSelector(bodyPadded, selector)) / 64) * 64;
  const precomputeText = bodyPadded.slice(0, shaCutoffIndex);
  let bodyRemaining = bodyPadded.slice(shaCutoffIndex);
  const bodyRemainingLen = bodyPaddedLen - precomputeText.length;
  console.log(bodyPaddedLen);
  console.log(precomputeText.length);
  console.log(bodyRemainingLen, " bytes remaining in body");
  console.log(MAX_BODY_PADDED_BYTES_FOR_EMAIL_TYPE);
  assert(
    bodyRemainingLen < MAX_BODY_PADDED_BYTES_FOR_EMAIL_TYPE,
    "Invalid slice"
  );
  assert(
    bodyRemaining.length % 64 === 0,
    "Not going to be padded correctly with int64s"
  );
  bodyRemaining = padWithZero(
    bodyRemaining,
    MAX_BODY_PADDED_BYTES_FOR_EMAIL_TYPE
  );
  assert(
    bodyRemaining.length === MAX_BODY_PADDED_BYTES_FOR_EMAIL_TYPE,
    "Invalid slice"
  );
  const bodyShaPrecompute = await partialSha(precomputeText, shaCutoffIndex);

  // Compute identity revealer
  let circuitInputs: ICircuitInputs;
  const modulus = toCircomBigIntBytes(modulusBigInt);
  const signature = toCircomBigIntBytes(signatureBigInt);

  const in_len_padded_bytes = messagePaddedLen.toString();
  const in_padded = await Uint8ArrayToCharArray(messagePadded); // Packed into 1 byte signals
  const in_body_len_padded_bytes = bodyRemainingLen.toString();
  const in_body_padded = await Uint8ArrayToCharArray(bodyRemaining);
  const base_message = toCircomBigIntBytes(postShaBigintUnpadded);
  const precomputed_sha = await Uint8ArrayToCharArray(bodyShaPrecompute);
  const body_hash_idx = bufferToString(message).indexOf(body_hash).toString();

  let raw_header = Buffer.from(prehash_message_string).toString();
  const email_from_idx =
    raw_header.length -
    trimStrByStr(trimStrByStr(raw_header, "from:"), "<").length;

  if (circuit == CircuitType.EMAIL_WISE_SEND) {
    const email_timestamp_idx = (
      raw_header.length - trimStrByStr(raw_header, "t=").length
    ).toString();

    const reference_code_selector = Buffer.from(`28px;">zkp2p-`);
    const reference_code_idx = (
      Buffer.from(bodyRemaining).indexOf(reference_code_selector) +
      reference_code_selector.length
    ).toString();
    const wise_amount_selector = Buffer.from("You received ");
    const wise_amount_idx = (
      Buffer.from(bodyRemaining).indexOf(wise_amount_selector) +
      wise_amount_selector.length
    ).toString();
    circuitInputs = {
      in_padded,
      modulus,
      signature,
      in_len_padded_bytes,
      precomputed_sha,
      in_body_padded,
      in_body_len_padded_bytes,
      body_hash_idx,

      reference_code_idx,
      wise_amount_idx,
      email_from_idx,
      email_timestamp_idx,
      // venmo specific indices
    };
  }
  return {
    circuitInputs,
    valid: {},
  };
}

export async function generate_input(email) {
  //console.log(`Generating inputs for ${payment_type} ${circuit_type} with email file ${email_file}`)
  //console.log("Email file read");

  const emailVerifierInputs = await generateEmailVerifierInputs(email.trim(), {
    ignoreBodyHashCheck: true,
  });
  const header = emailVerifierInputs.emailHeader!.map((c) => Number(c)); // Char array to Uint8Array
  // const body = emailVerifierInputs.emailBody!.map((c) => Number(c)); // Char array to Uint8Array

  const raw_header = Buffer.from(header);
  // const bodyRemaining = Buffer.from(body).toString();
  // console.log("trimStrByStr", trimStrByStr(raw_header, "t="));
  // const timestampSelectorBuffer = Buffer.from(STRING_PRESELECTOR);

  const fromSelectorBuffer = Buffer.from("from:Wise <");
  const email_from_idx =
    raw_header.indexOf(fromSelectorBuffer) + fromSelectorBuffer.length;
  const timestampSelectorBuffer = Buffer.from("; d=wise.com; t=");

  const email_timestamp_idx =
    raw_header.indexOf(timestampSelectorBuffer) +
    timestampSelectorBuffer.length;

  // const reference_code_selector = Buffer.from(`28px;">zkp2p-`);
  // const reference_code_idx = (
  //   Buffer.from(bodyRemaining).indexOf(reference_code_selector) +
  //   reference_code_selector.length
  // ).toString();
  // const wise_amount_selector = Buffer.from("You received ");
  // const wise_amount_idx = (
  //   Buffer.from(bodyRemaining).indexOf(wise_amount_selector) +
  //   wise_amount_selector.length
  // ).toString();
  // console.log(wise_amount_idx);
  // console.log(reference_code_idx);
  // console.log(emailVerifierInputs.emailBody.length);
  console.log("Input generation successful");
  return {
    ...emailVerifierInputs,
    email_from_idx,
    email_timestamp_idx,

    // wise_amount_idx,
    // reference_code_idx,
  };
}

export async function prove(eml: string): Promise<boolean> {
  try {
    const input = await generate_input(eml);
    // console.log(input);
    console.log("Input generated");

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      "./build/wise_send_js/wise_send.wasm",
      "./wise_send.zkey"
    );
    console.log("Proof: ", publicSignals);
    console.log(JSON.stringify(proof, null, 1));
    const vKey = JSON.parse(fs.readFileSync("./wise_send_vkey.json", "utf8"));
    console.log("vKey", vKey);

    const result = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    console.log("Result: ", result);
  } catch (err) {
    console.log(err);
    return false;
  }
}

function convertPackedBytesToString(packedBytes, signals, packSize) {
  console.log(packedBytes);
  let state = 0;
  let nonzeroBytesArray = [];
  let nonzeroBytesArrayIndex = 0;

  for (let i = 0; i < packedBytes.length; i++) {
    let packedByte = packedBytes[i];
    console.log("packedByte", packedByte);
    let unpackedBytes = [];

    for (let j = 0; j < packSize; j++) {
      console.log("packedByte1", packedByte);
      console.log("packedByte3", Number(packedByte & BigInt(0xff)));
      unpackedBytes.push(Number(packedByte & BigInt(0xff))); // Mask to get the lowest byte
      packedByte >>= BigInt(8);
      console.log("packedByte2", packedByte);
    }
    console.log(unpackedBytes);

    for (let j = 0; j < unpackedBytes.length; j++) {
      let unpackedByte = unpackedBytes[j];
      console.log(unpackedByte);
      console.log(String.fromCharCode(unpackedByte));
      if (unpackedByte !== 0) {
        nonzeroBytesArray[nonzeroBytesArrayIndex] =
          String.fromCharCode(unpackedByte);
        nonzeroBytesArrayIndex++;
        if (state % 2 === 0) {
          state += 1;
        }
      } else {
        if (state % 2 === 1) {
          state += 1;
        }
      }
    }
  }

  if (!(state === 1 || state === 2)) {
    throw new Error(
      "Invalid final state of packed bytes; more than two non-zero regions found!"
    );
  }

  if (nonzeroBytesArrayIndex > signals) {
    throw new Error("Packed bytes more than allowed max number of signals!");
  }

  return nonzeroBytesArray.join("");
}
async function serializeWithMode64Bit(
  bigInt: bigint,
  writer: Writable,
  compress: any
): Promise<void> {
  return new Promise((resolve, reject) => {
    const buffer = Buffer.alloc(8); // Allocate a buffer for 64-bit integer
    buffer.writeBigUInt64LE(bigInt); // This method is used for BigInt to ensure all 64 bits are written correctly in little-endian format

    writer.write(buffer, (error) => {
      if (error) {
        reject(new SerializationError("Failed to write to stream"));
      } else {
        resolve();
      }
    });
  });
}

async function readBigIntFromJson(filePath: string): Promise<BigInt> {
  try {
    const fileContent = await fs.readFileSync(filePath, "utf8");
    const data = JSON.parse(fileContent);
    return BigInt(data.number);
  } catch (error) {
    throw new SerializationError(
      "Failed to read or parse JSON file: " + error.message
    );
  }
}

async function serializeBigIntToBuffer(bigInt: bigint): Promise<Buffer> {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(bigInt);
  return buffer;
}

async function main() {
  // const toDomainPack = [];
  // const toDomainIndexInSignals = 1;
  // const signals = [
  //   "6183723068847575308396044429768161140368715965881107605538522343995188462295",
  //   "145464208126296943694313998845081710446",
  //   "251230042135255011374897",
  // ];
  // for (let i = toDomainIndexInSignals; i < toDomainIndexInSignals + 1; i++) {
  //   toDomainPack.push(BigInt(signals[i])); // Assuming 'signals' is an array of BigInts
  // }
  // const messageBytes = convertPackedBytesToString(toDomainPack, 31 * 1, 31);
  // console.log(messageBytes);
  // const eml = fs.readFileSync("./emls/wise.eml", "utf8");
  // await prove(eml);
  const filePath = "./verification_key.json";

  try {
    const bigInt = await readBigIntFromJson(filePath);
    const buffer = await serializeBigIntToBuffer(bigInt);
    console.log("Buffer:", buffer);
  } catch (error) {
    console.error("Error:", error);
  }
}

main();
