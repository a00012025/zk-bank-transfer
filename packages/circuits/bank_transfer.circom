pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/common/from_addr_regex.circom";
include "@zk-email/circuits/email-verifier.circom";
include "./components/fubon_transfer_regex.circom";
include "./utils/hash_sign_gen_rand.circom";
include "./utils/email_nullifier.circom";

// Here, n and k are the biginteger parameters for RSA
// This is because the number is chunked into k pack_size of n bits each
// Max header bytes shouldn't need to be changed much per email,
// but the max mody bytes may need to be changed to be larger if the email has a lot of i.e. HTML formatting
template FubonTransferVerifier(max_header_bytes, max_body_bytes, n, k, pack_size, expose_from, expose_to) {
    assert(expose_from < 2); // 1 if we should expose the from, 0 if we should not
    assert(expose_to == 0); // 1 if we should expose the to, 0 if we should not: due to hotmail restrictions, we force-disable this

    signal input in_padded[max_header_bytes]; // prehashed email data, includes up to 512 + 64? bytes of padding pre SHA256, and padded with lots of 0s at end after the length
    signal input pubkey[k]; // rsa pubkey, verified with smart contract + DNSSEC proof. split up into k parts of n bits each.
    signal input signature[k]; // rsa signature. split up into k parts of n bits each.
    signal input in_len_padded_bytes; // length of in email data including the padding, which will inform the sha256 block length

    // Identity commitment variables
    // (note we don't need to constrain the + 1 due to https://geometry.xyz/notebook/groth16-malleability)
    signal input address;
    signal input body_hash_idx;
    signal input precomputed_sha[32];
    signal input in_body_padded[max_body_bytes];
    signal input in_body_len_padded_bytes;

    signal output pubkey_hash;

    component EV = EmailVerifier(max_header_bytes, max_body_bytes, n, k, 0);
    EV.in_padded <== in_padded;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    EV.in_len_padded_bytes <== in_len_padded_bytes;
    EV.body_hash_idx <== body_hash_idx;
    EV.precomputed_sha <== precomputed_sha;
    EV.in_body_padded <== in_body_padded;
    EV.in_body_len_padded_bytes <== in_body_len_padded_bytes;

    pubkey_hash <== EV.pubkey_hash;
    signal header_hash[256] <== EV.sha;

    // FROM HEADER REGEX: 736,553 constraints
    // This extracts the from email, and the precise regex format can be viewed in the README
    if(expose_from){
        var max_email_from_len = 30;
        var max_email_from_packed_bytes = count_packed(max_email_from_len, pack_size);
        assert(max_email_from_packed_bytes < max_header_bytes);

        signal input email_from_idx;
        signal output reveal_email_from_packed[max_email_from_packed_bytes]; // packed into 7-bytes. TODO: make this rotate to take up even less space

        signal (from_regex_out, from_regex_reveal[max_header_bytes]) <== FromAddrRegex(max_header_bytes)(in_padded);
        log(from_regex_out);
        from_regex_out === 1;
        reveal_email_from_packed <== ShiftAndPackMaskedStr(max_header_bytes, max_email_from_len, pack_size)(from_regex_reveal, email_from_idx);
    }

    // Body reveal vars: Amount and Bank Account
    signal input transfer_amount_idx;
    signal input bank_account_idx;
    var max_amount_len = 12;
    var max_bank_account_len = 14;
    // array lengths are harcoded to 1 because 12 and 14 are less than 31
    signal output reveal_amount_packed[1];
    signal bank_account_packed[1];
    signal (regex_out, amount_regex_reveal[max_body_bytes], bank_account_regex_reveal[max_body_bytes]) <== FubonTransferRegex(max_body_bytes)(in_body_padded);
    
    // Ensures we found a match at least once (i.e. match count is not zero)
    signal is_found <== IsZero()(regex_out);
    is_found === 0;
    
    // PACKING: ??? constraints
    reveal_amount_packed <== ShiftAndPackMaskedStr(max_body_bytes, max_amount_len, pack_size)(amount_regex_reveal, transfer_amount_idx);
    bank_account_packed <== ShiftAndPackMaskedStr(max_body_bytes, max_bank_account_len, pack_size)(bank_account_regex_reveal, bank_account_idx);
    
    // HASH BANK ACCOUNT: ??? constraints
    component bank_account_hash = Poseidon(1);
    bank_account_hash.inputs[0] <== bank_account_packed[0];
    signal output reveal_bank_account_hashed <== bank_account_hash.out;

    // NULLIFIER: ??? constraints
    signal output email_nullifier;
    signal cm_rand <== HashSignGenRand(n, k)(signature);
    email_nullifier <== EmailNullifier()(header_hash, cm_rand);
}

// In circom, all output signals of the main component are public (and cannot be made private), the input signals of the main component are private if not stated otherwise using the keyword public as above. The rest of signals are all private and cannot be made public.
// This makes pubkey_hash and reveal_amount_packed public. hash(signature) can optionally be made public, but is not recommended since it allows the mailserver to trace who the offender is.

// TODO: Update deployed contract and zkey to reflect this number, as it the currently deployed contract uses 7
// Args:
// * max_header_bytes = 1024 is the max number of bytes in the header
// * max_body_bytes = 14528 is the max number of bytes in the body after precomputed slice
// * n = 121 is the number of bits in each chunk of the pubkey (RSA parameter)
// * k = 17 is the number of chunks in the pubkey (RSA parameter). Note 121 * 17 > 2048.
// * pack_size = 31 is the number of bytes that can fit into a 255ish bit signal (can increase later)
// * expose_from = 0 is whether to expose the from email address
// * expose_to = 0 is whether to expose the to email (not recommended)
component main { public [ address ] } = FubonTransferVerifier(1024, 14528, 121, 17, 31, 0, 0);
