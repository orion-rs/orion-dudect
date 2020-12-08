# stable
cargo clean;
mkdir bench-results;
RUSTFLAGS="-C $1" cargo run --release --bin ct_benches > bench-results/ct_benches.txt;
cargo test -- --nocapture;

# nightly
cargo clean;
mkdir bench-results;
RUSTFLAGS="-C $1" cargo +nightly run --release --bin ct_benches > bench-results/ct_benches.txt;
cargo test -- --nocapture;