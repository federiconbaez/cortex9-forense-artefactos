#![no_main]
use libfuzzer_sys::fuzz_target;
use forense_artefactos::crypto::{hmac_sha256, sha256};
use forense_artefactos::pin_counter::{LockState, PinCounter, PinPolicy};
use forense_artefactos::rpmb::{RpmbDevice, RPMB_DATA_LEN};

fuzz_target!(|data: &[u8]| {
    let _ = sha256(data);
    let _ = hmac_sha256(data.get(..32).unwrap_or(b"k"), data);
    if data.len() >= 4 {
        let mut c = PinCounter::new(PinPolicy::default(), data[..4].to_vec(), LockState::Bfu);
        let _ = c.attempt(data.get(4..8).unwrap_or(b"xxxx"));
    }
    if data.len() >= 32 + RPMB_DATA_LEN {
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[..32]);
        let mut block = [0u8; RPMB_DATA_LEN];
        block.copy_from_slice(&data[32..32 + RPMB_DATA_LEN]);
        let mut d = RpmbDevice::new(key, 2);
        let f = d.sign_write(0, 0, block);
        let _ = d.authenticated_write(&f);
    }
});
