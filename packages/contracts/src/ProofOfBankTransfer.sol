// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import "@zk-email/contracts/utils/StringUtils.sol";
import {Verifier} from "./Verifier.sol";

contract ProofOfBankTransfer {
    using StringUtils for *;

    uint16 public constant bytesInPackedBytes = 31;
    string constant domain = "dfm.taipeifubon.com.tw";

    uint32 public constant pubKeyHashIndexInSignals = 0; // index of DKIM public key hash in signals array
    uint32 public constant amountIndexInSignals = 1; // index of packed transfer amount in signals array
    uint32 public constant addressIndexInSignals = 2; // index of ethereum address in signals array

    DKIMRegistry dkimRegistry;
    Verifier public immutable verifier;

    mapping(address => uint256) public addressToAmount;

    event AmountProved(address indexed sender, uint256 amount);

    constructor(Verifier v, DKIMRegistry d) {
        verifier = v;
        dkimRegistry = d;
    }

    /// Prove the amount transfer from bank
    /// @param proof ZK proof of the circuit - a[2], b[4] and c[2] encoded in series
    /// @param signals Public signals of the circuit. First item is pubkey_hash, next is amount, the last one is etherum address
    function prove(uint256[8] memory proof, uint256[3] memory signals) public {
        // Checks: Verify proof and check signals
        // public signals are the masked packed message bytes, and hash of public key.
        // Verify the DKIM public key hash stored on-chain matches the one used in circuit
        bytes32 dkimPublicKeyHashInCircuit = bytes32(
            signals[pubKeyHashIndexInSignals]
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

        // Extract the amount chunks from the signals.
        uint256[] memory amountPacked = new uint256[](1);
        amountPacked[0] = signals[amountIndexInSignals];
        string memory amountStr = StringUtils.convertPackedBytesToString(
            amountPacked,
            bytesInPackedBytes,
            bytesInPackedBytes
        );
        uint256 amount = StringUtils.stringToUint(amountStr);
        addressToAmount[msg.sender] += amount;
        emit AmountProved(msg.sender, amount);
    }
}
