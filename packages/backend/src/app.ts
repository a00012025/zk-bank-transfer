import express, { Request, Response } from "express";
import bodyParser from "body-parser";
import multer, { FileFilterCallback } from "multer";
import { verifyDKIMSignature } from "@/packages/circuits/helpers/dkim";
import { generateBankTransferVerifierCircuitInputs } from "@/packages/circuits/helpers";
import fs from "fs-extra";
import shell from "shelljs";
import path from "path";

const PROOF_DIR = path.join(__dirname, "./proofs");
const upload = multer({ dest: "uploads/" });

// Ensure proof directory exists
fs.ensureDirSync(PROOF_DIR);

const app = express();
app.use(bodyParser.json());

// Middleware to handle file and Ethereum address upload
app.post(
  "/prove_email",
  upload.single("file"),
  async (req: Request, res: Response) => {
    if (!req.file || !req.body.ethereumAddress) {
      return res
        .status(400)
        .send({ error: "EML file and Ethereum address are required" });
    }

    try {
      const rawEmail = await fs.readFile(req.file.path);
      const ethereumAddress = req.body.ethereumAddress as string;

      const dkimResult = await verifyDKIMSignature(rawEmail);
      const circuitInputs = await generateBankTransferVerifierCircuitInputs({
        rsaSignature: dkimResult.signature,
        rsaPublicKey: dkimResult.publicKey,
        body: dkimResult.body,
        bodyHash: dkimResult.bodyHash,
        message: dkimResult.message,
        ethereumAddress: ethereumAddress,
      });

      const currentTime = Math.floor(Date.now() / 1000).toString();
      const inputFilePath = `${PROOF_DIR}/${currentTime}_input.json`;
      const buildDir = path.join(__dirname, "../../circuits/build");
      await fs.writeJson(inputFilePath, circuitInputs);

      const scriptResult = shell.exec(
        `./circom_proofgen.sh bank_transfer ${inputFilePath} ${buildDir} 0`,
        { silent: false }
      );
      console.log(scriptResult);

      if (scriptResult.code !== 0) {
        return res.status(500).send({ error: "Error generating proof" });
      }

      const proofFilePath = `${PROOF_DIR}/${currentTime}_bank_transfer_proof.json`;
      const publicInputsFilePath = `${PROOF_DIR}/${currentTime}_bank_transfer_public.json`;

      const circuitProof = await fs.readJson(proofFilePath);
      const circuitPublicInputs = await fs.readJson(publicInputsFilePath);

      res.send({ proof: circuitProof, public_inputs: circuitPublicInputs });
    } catch (error) {
      console.error(error);
      res.status(500).send({ error: "Internal server error" });
    }
  }
);

const port = 8080;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
