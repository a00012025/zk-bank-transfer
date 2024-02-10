import { bytesToBigInt, fromHex } from "@zk-email/helpers/dist/binaryFormat";
import { generateCircuitInputs } from "@zk-email/helpers/dist/input-helpers";

export const STRING_PRESELECTOR =
  "=e8=\r\n=bd=89=e5=b8=b3=e9=87=91=e9=a1=8d</td>=0a=09=09<td>=0a=09=09=09=09=09=09=e8=\r\n=87=ba=e5=b9=a3=20";
const BANK_ID_PREFIX = "</td>=0a=09=09=09=09<td>=0a=09=09=09";
export const MAX_HEADER_PADDED_BYTES = 1024; // NOTE: this must be the same as the first arg in the email in main args circom
export const MAX_BODY_PADDED_BYTES = 14528; // NOTE: this must be the same as the arg to sha the remainder number of bytes in the email in main args circom

export type IBankTransferCircuitInputs = ReturnType<
  typeof generateBankTransferVerifierCircuitInputs
>;

export function generateBankTransferVerifierCircuitInputs({
  rsaSignature,
  rsaPublicKey,
  body,
  bodyHash,
  message, // the message that was signed (header + bodyHash)
  ethereumAddress,
}: {
  body: Buffer;
  message: Buffer;
  bodyHash: string;
  rsaSignature: BigInt;
  rsaPublicKey: BigInt;
  ethereumAddress: string;
}) {
  const emailVerifierInputs = generateCircuitInputs({
    rsaSignature,
    rsaPublicKey,
    body,
    bodyHash,
    message,
    shaPrecomputeSelector: STRING_PRESELECTOR,
    maxMessageLength: MAX_HEADER_PADDED_BYTES,
    maxBodyLength: MAX_BODY_PADDED_BYTES,
  });

  const bodyRemaining = emailVerifierInputs.in_body_padded!.map((c) =>
    Number(c)
  ); // Char array to Uint8Array
  const selectorBuffer = Buffer.from(STRING_PRESELECTOR);

  const transfer_amount_idx =
    Buffer.from(bodyRemaining).indexOf(selectorBuffer) + selectorBuffer.length;

  const bank_id_idx =
    Buffer.from(bodyRemaining).indexOf(BANK_ID_PREFIX, selectorBuffer.length) +
    BANK_ID_PREFIX.length;
  const bank_account_idx = bank_id_idx + 45;

  const address = bytesToBigInt(fromHex(ethereumAddress)).toString();

  return {
    ...emailVerifierInputs,
    transfer_amount_idx,
    bank_account_idx,
    address,
  };
}
