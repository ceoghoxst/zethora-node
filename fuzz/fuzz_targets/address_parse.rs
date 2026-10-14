#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Address parsing takes attacker-controlled text (user input, RPC calls,
    // block explorer URLs). Feed random bytes as a UTF-8 string when possible.
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<kaspa_addresses::Address, _> = s.try_into();
    }
});