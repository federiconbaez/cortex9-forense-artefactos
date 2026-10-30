use fa_core::crypto::sha256;
use fa_pate::Transcript;
use std::fs;

#[test]
fn e2e_with_sample_artifacts() {
    let dir = std::env::temp_dir().join("pate-e2e");
    let _ = fs::create_dir_all(&dir);
    let art = dir.join("sample.bin");
    fs::write(&art, b"evidence-bytes").unwrap();
    let digest = sha256(b"evidence-bytes");
    let hex = {
        use std::fmt::Write;
        let mut s = String::with_capacity(64);
        for b in &digest { let _ = write!(s, "{:02x}", b); }
        s
    };

    let mut t = Transcript::init("E2E-1");
    t.append(
        "acquire",
        "sample.bin",
        "2026-10-29T20:00:00-03:00",
        "perito",
        "demo",
        &hex,
    )
    .unwrap();
    t.seal("perito", "2026-10-29T20:01:00-03:00").unwrap();
    assert!(t.verify().is_ok());
    let md = t.to_markdown();
    assert!(md.contains("E2E-1"));
    let json_path = dir.join("t.json");
    fs::write(&json_path, t.to_json().unwrap()).unwrap();
    let t2 = Transcript::from_json(&fs::read_to_string(json_path).unwrap()).unwrap();
    assert!(t2.verify().is_ok());
}
