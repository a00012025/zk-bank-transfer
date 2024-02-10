// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import "@zk-email/contracts/utils/StringUtils.sol";
import {Groth16Verifier} from "./Verifier.sol";

contract OTCByBankTransfer is Ownable {
    uint16 public constant bytesInPackedBytes = 31;
    string constant domain = "dfm.taipeifubon.com.tw";

    uint32 public constant pubKeyHashIndexInSignal = 0; // index of DKIM public key hash in signals array
    uint32 public constant amountIndexInSignal = 1; // index of packed transfer amount in signals array
    uint32 public constant bankIdIndexInSignal = 2; // index of hashed bank id in signals array
    uint32 public constant bankAccountIndexInSignal = 3; // index of hashed bank account in signals array
    uint32 public constant emailNullifierIndexInSignal = 4; // index of email nullifier in signals array
    uint32 public constant addressIndexInSignal = 5; // index of ethereum address in signals array

    DKIMRegistry dkimRegistry;
    Groth16Verifier public immutable verifier;
    ERC20 public immutable USDT;
    // rate times 1000
    uint256 public usdtToTwdRate;

    event AmountProved(address indexed sender, uint256 amount);

    constructor(Groth16Verifier v, DKIMRegistry d, address usdt) {
        verifier = v;
        dkimRegistry = d;
        USDT = ERC20(usdt);
        usdtToTwdRate = 31_788;
    }

    // set usdt rate
    function setUsdtToTwdRate(uint256 rate) public onlyOwner {
        usdtToTwdRate = rate;
    }

    /// Prove the amount transfer from bank
    /// @param proof ZK proof of the circuit - a[2], b[4] and c[2] encoded in series
    /// @param signals Public signals of the circuit. First item is pubkey_hash, next is amount, the last one is etherum address
    function prove(uint256[8] memory proof, uint256[5] memory signals) public {
        // Checks: Verify proof and check signals
        // public signals are the masked packed message bytes, and hash of public key.
        // Verify the DKIM public key hash stored on-chain matches the one used in circuit
        bytes32 dkimPublicKeyHashInCircuit = bytes32(
            signals[pubKeyHashIndexInSignal]
        );
        require(
            dkimRegistry.isDKIMPublicKeyHashValid(
                domain,
                dkimPublicKeyHashInCircuit
            ),
            "invalid dkim signature"
        );

        // Veiry RSA and proof
        require(
            verifier.verifyProof(
                [proof[0], proof[1]],
                [[proof[2], proof[3]], [proof[4], proof[5]]],
                [proof[6], proof[7]],
                signals
            ),
            "Invalid Proof"
        );

        // Verify bank id and account
        // TODO: add hashed bank id and account
        require(signals[bankIdIndexInSignal] == 1234, "Invalid bank id");
        require(
            signals[bankAccountIndexInSignal] == 1234,
            "Invalid bank account"
        );

        // Extract the amount chunks from the signals.
        uint256[] memory amountPacked = new uint256[](1);
        amountPacked[0] = signals[amountIndexInSignal];
        string memory amountStr = StringUtils.convertPackedBytesToString(
            amountPacked,
            bytesInPackedBytes,
            bytesInPackedBytes
        );
        uint256 amount = StringUtils.stringToUint(amountStr);
        emit AmountProved(msg.sender, amount);

        // calculate USDT to send
        uint256 usdtToSend = (amount * 1000 * 10 ** (USDT.decimals())) /
            usdtToTwdRate;
        USDT.transfer(msg.sender, usdtToSend);
    }
}
