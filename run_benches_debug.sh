# stable
cargo clean;
mkdir bench-results;
RUSTFLAGS="-C $1" cargo run --bin ct_benches > bench-results/ct_benches.txt;
cargo test -- --nocapture;

# nightly
cargo clean;
mkdir bench-results;
RUSTFLAGS="-C $1" cargo +nightly run --bin ct_benches > bench-results/ct_benches.txt;
cargo test -- --nocapture;