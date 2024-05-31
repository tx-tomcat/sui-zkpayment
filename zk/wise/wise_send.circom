pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/email-verifier.circom";
include "@zk-email/zk-regex-circom/circuits/common/from_addr_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/timestamp_regex.circom";
include "@zk-email/zk-regex-circom/circuits/common/to_addr_regex.circom";
// include "./regexes/wise_reference_code.circom";
// include "./regexes/wise_amount_send.circom";
// include "./regexes/wise_timestamp.circom";
template WiseSendEmail(max_header_bytes, max_body_bytes, n, k, ignore_body_hash_check) {

    // Rounded to the nearest multiple of pack_size for extra room in case of change of constants
    // var max_email_amount_len = 8; // Allowing max 4 fig amount + one decimal point + 2 decimal places. e.g. $2,500.00
    var max_email_from_len = 255; // RFC 2821: requires length to be 254, but we can limit to 21 (wise@wise.com)
    var max_email_timestamp_len = 10; // 10 digits till year 2286
    // var max_reference_code_len = 10;

    signal input emailHeader[max_header_bytes];
    signal input emailHeaderLength;
    signal input pubkey[k];
    signal input signature[k];
    // signal input emailBody[max_body_bytes];
    // signal input emailBodyLength;
    // signal input bodyHashIndex;
    // signal input precomputedSHA[32];
    signal output pubkeyHash;

    // DKIM VERIFICATION
    component EV = EmailVerifier(max_header_bytes, max_body_bytes, n, k, ignore_body_hash_check);
    EV.emailHeader <== emailHeader;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    EV.emailHeaderLength <== emailHeaderLength;
    // EV.bodyHashIndex <== bodyHashIndex;
    // EV.precomputedSHA <== precomputedSHA;
    // EV.emailBody <== emailBody;
    // EV.emailBodyLength <== emailBodyLength;

    pubkeyHash <== EV.pubkeyHash;

    signal input email_from_idx;
    signal (from_regex_out, from_regex_reveal[max_header_bytes]) <== FromAddrRegex(max_header_bytes)(emailHeader);
    from_regex_out === 1;
    signal reveal_email_from_packed[9] <== PackRegexReveal(max_header_bytes, max_email_from_len)(from_regex_reveal, email_from_idx);
    signal output from_email <== reveal_email_from_packed[0];

    //WISE TIMESTAMP
    signal input email_timestamp_idx;
    signal (timestamp_regex_out, timestamp_regex_reveal[max_header_bytes]) <== TimestampRegex(max_header_bytes)(emailHeader);
    log(timestamp_regex_out);
    log("finding... timestamp_regex_out");
    timestamp_regex_out === 1;
    log("timestamp_regex_out Found");
    signal reveal_email_timestamp_packed[1] <== PackRegexReveal(max_header_bytes, max_email_timestamp_len)(timestamp_regex_reveal, email_timestamp_idx);
    signal output wise_timestamp <== reveal_email_timestamp_packed[0];


    // //WISE REFERENCE CODE
    // signal input reference_code_idx;
    // signal reference_code_regex_out, reference_code_regex_reveal[max_body_bytes];
    // (reference_code_regex_out, reference_code_regex_reveal) <== WiseReferenceCodeRegex(max_body_bytes)(emailBody);
    // reference_code_regex_out === 1;
    // signal reveal_reference_code_packed[1] <== PackRegexReveal(max_body_bytes, max_reference_code_len)(reference_code_regex_reveal, reference_code_idx);
    // signal output wise_reference_code <== reveal_reference_code_packed[0];

    // //WISE AMOUNT
    // signal input wise_amount_idx;
    // signal amount_regex_out, amount_regex_reveal[max_body_bytes];
    // (amount_regex_out, amount_regex_reveal) <== WiseSendAmountRegex(max_body_bytes)(emailBody);
    // amount_regex_out === 1;
    // signal reveal_email_amount_packed[1] <== PackRegexReveal(max_body_bytes, max_email_amount_len)(amount_regex_reveal, wise_amount_idx);
    // signal output wise_amount <== reveal_email_amount_packed[0];
}

// Args:
// * max_header_bytes = 1024 is the max number of bytes in the header
// * max_body_bytes = 6272 is the max number of bytes in the body after precomputed slice (Need to leave room for >280 char custom message)
// * n = 121 is the number of bits in each chunk of the modulus (RSA parameter)
// * k = 17 is the number of chunks in the modulus (RSA parameter)
// * pack_size = 7 is the number of bytes that can fit into a 255ish bit signal (can increase later)
component main = WiseSendEmail(1024, 1536, 121, 17, 1);