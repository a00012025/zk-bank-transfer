import { program } from "commander";
import fs from "fs";
import path from "path";
import { generateBankTransferVerifierCircuitInputs } from "../helpers";
import { verifyDKIMSignature } from "../helpers/dkim";

program
  .requiredOption("--email-file <string>", "Path to email file")
  .requiredOption(
    "--ethereum-address <string>",
    "Ethereum address to verify twitter handle against"
  )
  .option("--silent", "No console logs");

program.parse();
const args = program.opts();

const OUTPUT_DIR = path.join(__dirname, "../proofs");

function log(...message: any) {
  if (!args.silent) {
    console.log(...message);
  }
}
const logger = { log, error: log, warn: log, debug: log };

async function generate() {
  if (!fs.existsSync(args.emailFile)) {
    throw new Error("--input file path arg must end with .json");
  }

  log("Generating input and proof for:", args.emailFile);

  const rawEmail = Buffer.from(fs.readFileSync(args.emailFile, "utf8"));
  const dkimResult = await verifyDKIMSignature(rawEmail);

  const circuitInputs = await generateBankTransferVerifierCircuitInputs({
    rsaSignature: dkimResult.signature,
    rsaPublicKey: dkimResult.publicKey,
    body: dkimResult.body,
    bodyHash: dkimResult.bodyHash,
    message: dkimResult.message,
    ethereumAddress: args.ethereumAddress,
  });

  log("\n\nGenerated Inputs:", circuitInputs, "\n\n");

  fs.writeFileSync(
    path.join(OUTPUT_DIR, "input.json"),
    JSON.stringify(circuitInputs, null, 2)
  );
  log("Inputs written to", path.join(OUTPUT_DIR, "input.json"));

  process.exit(0);
}

generate().catch((err) => {
  console.error("Error generating inputs", err);
  process.exit(1);
});
