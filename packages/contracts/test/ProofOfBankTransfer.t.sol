// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import "../src/ProofOfBankTransfer.sol";
import "../src/Verifier.sol";

contract TwitterUtilsTest is Test {
    using StringUtils for *;

    address constant VM_ADDR = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D; // Hardcoded address of the VM from foundry

    Verifier proofVerifier;
    DKIMRegistry dkimRegistry;
    ProofOfBankTransfer testVerifier;

    uint16 public constant packSize = 7;

    function setUp() public {
        proofVerifier = new Verifier();
        dkimRegistry = new DKIMRegistry();

        // These are the Poseidon hash of DKIM public keys for domain
        // This was calcualted using https://github.com/zkemail/zk-email-verify/tree/main/packages/scripts
        dkimRegistry.setDKIMPublicKeyHash(
            "dfm.taipeifubon.com.tw",
            bytes32(
                uint256(
                    8521093304904949094417505179913007927512696611747706107671813586064928938549
                )
            )
        );

        testVerifier = new ProofOfBankTransfer(proofVerifier, dkimRegistry);
    }

    // These proof and public input values are generated using scripts in packages/circuits/scripts/generate-proof.ts
    // The sample email in `/emls` is used as the input, but you will have different values if you generated your own zkeys
    function testVerifyTestEmail() public {
        uint256[3] memory publicSignals;
        publicSignals[
            0
        ] = 8521093304904949094417505179913007927512696611747706107671813586064928938549;
        publicSignals[1] = 52983524766513;
        publicSignals[2] = 51410588117056328271986241639848257252558396979;

        uint256[2] memory proof_a = [
            8560515785464264484566975251793601340764569587346456836887462574095272861109,
            9187213949652534260402406992756428277971510758385929929393362206660112986577
        ];
        // Note: you need to swap the order of the two elements in each subarray
        uint256[2][2] memory proof_b = [
            [
                4622418497485476916317506827917430058883769016004496189211095203943796358240,
                1486080943321564848486974282840661162948885585134536897142796223606316279220
            ],
            [
                16036348385538987582074595152306129305342020105012444996767041124014470746773,
                11682939184801245044140099548815007763750418101414768278298851687451602118562
            ]
        ];
        uint256[2] memory proof_c = [
            5945751468291848331115504470783768396549824438334575486526039341389473938784,
            20682598462898495943003708847117032729823288172023493416264967628353000523940
        ];

        uint256[8] memory proof = [
            proof_a[0],
            proof_a[1],
            proof_b[0][0],
            proof_b[0][1],
            proof_b[1][0],
            proof_b[1][1],
            proof_c[0],
            proof_c[1]
        ];

        // Test proof verification
        bool verified = proofVerifier.verifyProof(
            proof_a,
            proof_b,
            proof_c,
            publicSignals
        );
        assertEq(verified, true);

        // Test prove after spoofing msg.sender
        Vm vm = Vm(VM_ADDR);
        vm.startPrank(0x0000000000000000000000000000000000000001);
        testVerifier.prove(proof, publicSignals);
        vm.stopPrank();
        uint256 amount = testVerifier.addressToAmount(
            address(0x0901549Bc297BCFf4221d0ECfc0f718932205e33)
        );
        console.log("Amount: ", amount);
    }
}
