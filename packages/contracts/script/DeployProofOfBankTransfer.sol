// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import "../src/ProofOfBankTransfer.sol";
import "../src/Verifier.sol";

contract Deploy is Script, Test {
    function getPrivateKey() internal view returns (uint256) {
        try vm.envUint("PRIVATE_KEY") returns (uint256 privateKey) {
            return privateKey;
        } catch {
            // This is the anvil default exposed secret key
            return
                0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        }
    }

    function run() public {
        uint256 sk = getPrivateKey();
        vm.startBroadcast(sk);

        Verifier proofVerifier = new Verifier();
        console.log("Deployed Verifier at address: %s", address(proofVerifier));

        DKIMRegistry dkimRegistry = new DKIMRegistry();
        console.log(
            "Deployed DKIMRegistry at address: %s",
            address(dkimRegistry)
        );

        dkimRegistry.setDKIMPublicKeyHash(
            "dfm.taipeifubon.com.tw",
            bytes32(
                uint256(
                    8521093304904949094417505179913007927512696611747706107671813586064928938549
                )
            )
        );

        ProofOfBankTransfer testVerifier = new ProofOfBankTransfer(
            proofVerifier,
            dkimRegistry
        );
        console.log(
            "Deployed ProofOfTwitter at address: %s",
            address(testVerifier)
        );

        vm.stopBroadcast();
    }
}
