//! Demo PATE-FNBR: init → append → seal → verify → markdown.
use fa_pate::Transcript;

fn main() {
    let mut t = Transcript::init("EXP-2026-001");
    t.append(
        "acquire",
        "full-file-system-declared",
        "2026-10-29T17:00:00-03:00",
        "F. Baez Rizzo",
        "lab-suite-X",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    t.append(
        "hash",
        "container.tar",
        "2026-10-29T17:02:00-03:00",
        "F. Baez Rizzo",
        "sha256sum",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    t.seal("F. Baez Rizzo", "2026-10-29T17:05:00-03:00")
        .unwrap();
    assert!(t.verify().is_ok());
    println!("{}", t.to_markdown());
}
