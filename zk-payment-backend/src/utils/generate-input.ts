import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { generateEmailVerifierInputs } from '@zk-email/helpers';

export async function generate_input(email) {
  const emailVerifierInputs = await generateEmailVerifierInputs(email, {
    ignoreBodyHashCheck: true,
  });
  const header = emailVerifierInputs.emailHeader!.map((c) => Number(c));

  const raw_header = Buffer.from(header);

  const fromSelectorBuffer = Buffer.from('from:Wise <');
  const email_from_idx =
    raw_header.indexOf(fromSelectorBuffer) + fromSelectorBuffer.length;
  const timestampSelectorBuffer = Buffer.from('; d=wise.com; t=');

  const email_timestamp_idx =
    raw_header.indexOf(timestampSelectorBuffer) +
    timestampSelectorBuffer.length;

  return {
    ...emailVerifierInputs,
    email_from_idx,
    email_timestamp_idx,
  };
}

export const ZKRAMP_ID =
  '0x3f45b7b243fcf99e3e812f7ad79b9f8a36135073348fc1f5d8023d8f9027c682';
export const ADMIN_CAP =
  '0x5df75b1a523957a0b78dad7716021341c8abbb0e803e7471eaeeda348116bdfd';
export const PUBLISHED_AT =
  '0x88dfad1e68a50ade5634883b4c6dfe90eab314e6260e881799f69ac3c101d5cd';
export const client = new SuiClient({
  url: getFullnodeUrl('testnet'),
});

export function jsonToHexString(json) {
  // Serialize the JSON object to a string
  const jsonString = JSON.stringify(json);

  // Convert the JSON string to a Buffer
  const buffer = Buffer.from(jsonString);

  // Convert the Buffer to a hexadecimal string
  const hexString = buffer.toString('hex');

  return hexString;
}
