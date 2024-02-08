import { bytesToBigInt, fromHex } from "@zk-email/helpers/dist/binaryFormat";
import { generateCircuitInputs } from "@zk-email/helpers/dist/input-helpers";

export const STRING_PRESELECTOR = "<td>=E8=BD=89=E5=B8=B3=E9=87=91=E9=A1=8D";
export const MAX_HEADER_PADDED_BYTES = 1024; // NOTE: this must be the same as the first arg in the email in main args circom
export const MAX_BODY_PADDED_BYTES = 1536; // NOTE: this must be the same as the arg to sha the remainder number of bytes in the email in main args circom

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
  transfer_amount_idx: string;
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

  let currentIndex =
    Buffer.from(bodyRemaining).indexOf(selectorBuffer) + selectorBuffer.length;
  // search "<td>" starting from after currentIndex
  currentIndex = Buffer.from(bodyRemaining).indexOf(
    Buffer.from("<td>"),
    currentIndex
  );
  const transfer_amount_idx = currentIndex + 4;

  const address = bytesToBigInt(fromHex(ethereumAddress)).toString();

  return {
    ...emailVerifierInputs,
    transfer_amount_idx,
    address,
  };
}
