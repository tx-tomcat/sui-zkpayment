module zkramp::string_utils {
    use std::string::{Self, String};

    public fun convert_packed_bytes_to_string(packed_bytes: vector<u8>, signals: u64 , pack_size: u64) : String {
        let mut state: u8 = 0;
        let mut nonzero_bytes: vector<u8> = vector::empty();
        let mut nonzero_bytes_index: u64 = 0;

        let len = vector::length(&packed_bytes);
        let mut i = 0;
        while (i < len) {
            let packed_byte = vector::borrow(&packed_bytes, i);
            let mut j: u64 = 0;
            while (j < pack_size) {
                let shift_amount = j * 8;
                let unpacked_byte = (*packed_byte  >> (shift_amount as u8)) & 0xFF ;
                if (unpacked_byte != 0) {
                    vector::push_back(&mut nonzero_bytes, unpacked_byte as u8);
                    nonzero_bytes_index = nonzero_bytes_index + 1;
                    if (state % 2 == 0) {
                        state = state + 1;
                    }
                } else {
                    if (state % 2 == 1) {
                        state = state + 1;
                    }
                };
                j = j + 1;
            };
            i = i + 1;
        };
        assert!(state >= 1, 1); // Error code 1 for no packed bytes found
        assert!(nonzero_bytes_index <= signals, 2); // Error code 2 for too many signals

        string::utf8(nonzero_bytes)
    }

    // Converts a string to u64. Assumes the string is a valid non-negative decimal number.
    public fun string_to_u64(s: String): u64 {
        let mut num: u64 = 0;
        let len = string::length(&s);
        let mut i = 0;

        while (i < len) {
            let bytes = *string::bytes(&s);
            let c = *vector::borrow(&bytes, i);
            let digit = char_to_digit(c);
            num = num * 10 + digit; // Shift left by one decimal place and add the new digit
            i = i + 1;
        };
        num
    }

    // Helper function to convert a character to its digit value
    fun char_to_digit(c: u8): u64 {
        // Check if the character is between '0' and '9'
        if (c >= 48 && c <= 57) {
            (c as u64) - 48
        } else {
            abort 1 // Aborts if the character is not a valid decimal digit
        }
    }


    #[test]
    fun test_packed_bytes_to_string(){
        // let mut signals = vector::empty();
        // vector::push_back(&mut signals, 6183723068847575308396044429768161140368715965881107605538522343995188462295);
        // vector::push_back(&mut signals, 145464208126296943694313998845081710446);
        // vector::push_back(&mut signals, 251230042135255011374897);
        // let to_domain_index_in_signals = 1; // Starting index is 0 in this case
        // let mut to_domain_pack = vector::empty();

        // let mut i = to_domain_index_in_signals;

        // while (i < to_domain_index_in_signals + 1) {
        //     vector::push_back(&mut to_domain_pack, *vector::borrow(&signals, i));
        //     i = i + 1;
        // };
        // let result = convert_packed_bytes_to_string(to_domain_pack, 31, 31);
        // assert!(result == string::utf8(b"noreply@wise.com"), 1);
    }
}