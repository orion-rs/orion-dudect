# stable
cargo clean;
mkdir -p bench-results;
RUSTFLAGS="-C $1" cargo run --bin ct_benches > bench-results/ct_benches.txt;
cargo test -- --nocapture;
rm -rf bench-results # Remove so we don't reparse the when nightly is run

# nightly
cargo clean;
mkdir -p bench-results;
RUSTFLAGS="-C $1" cargo +nightly run --bin ct_benches > bench-results/ct_benches.txt;
cargo test -- --nocapture;