#[macro_use]
extern crate dudect_bencher;
extern crate ct_codecs;
extern crate orion;
extern crate orion_dudect;
extern crate rand;

use std::convert::TryFrom;

use dudect_bencher::{BenchRng, Class, CtRunner};
use orion::hazardous::ecc::x25519::key_agreement;
use orion::hazardous::mac::poly1305::{OneTimeKey, Poly1305, POLY1305_KEYSIZE};
use orion::hazardous::stream::chacha20::{SecretKey, CHACHA_KEYSIZE};
use orion::pwhash::PWHASH_LENGTH;
use orion::util::secure_cmp;
use orion_dudect::{generate_input_classes, rand_input_vector, NUMBER_OF_SAMPLES};
// `Base64NoPadding` is the padding used in orion::pwhash::PasswordHash
use ct_codecs::{Base64NoPadding, Decoder, Encoder};
use rand::Rng;

// We only test one newtype that implements PartialEq, because they
// all use the macro to implement it.
fn test_newtype(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, CHACHA_KEYSIZE);

    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        let sk0 = SecretKey::from_slice(&u[..]).unwrap();
        let sk1 = SecretKey::from_slice(&v[..]).unwrap();
        runner.run_one(class, || sk0 == sk1);
    }
}

// We only test one newtype that implements PartialEq, because they
// all use the macro to implement it.
fn test_newtype_slice(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, CHACHA_KEYSIZE);

    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        let sk0 = SecretKey::from_slice(&u[..]).unwrap();
        runner.run_one(class, || sk0 == &v[..]);
    }
}

fn test_secure_cmp(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, 32);

    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || secure_cmp(&u[..], &v[..]).is_ok());
    }
}

fn test_poly1305(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, POLY1305_KEYSIZE);

    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        // u will be used as SecretKey and v as message to be authenticated.
        let sk = OneTimeKey::from_slice(&u[..]).unwrap();
        runner.run_one(class, || Poly1305::poly1305(&sk, &v[..]).unwrap());
    }
}

fn test_poly1305_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, POLY1305_KEYSIZE);

    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        // u will be used as SecretKey and v as message to be authenticated.
        let sk = OneTimeKey::from_slice(&u[..]).unwrap();
        let expected = Poly1305::poly1305(&sk, &v[..]).unwrap();

        runner.run_one(class, || Poly1305::verify(&expected, &sk, &v[..]).is_ok());
    }
}

fn test_ct_base64_encode(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, PWHASH_LENGTH);

    for (class, (u, _v)) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || Base64NoPadding::encode_to_string(&u[..]).unwrap());
    }
}

fn test_ct_base64_decode(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, PWHASH_LENGTH);

    for (class, (u, _v)) in classes.into_iter().zip(inputs.into_iter()) {
        let encoded = Base64NoPadding::encode_to_string(&u[..]).unwrap();

        runner.run_one(class, || {
            Base64NoPadding::decode_to_vec(encoded.as_str(), None).unwrap()
        });
    }
}

fn test_x25519_scalarmul_base(runner: &mut CtRunner, rng: &mut BenchRng) {
    use orion::hazardous::ecc::x25519::{PrivateKey, PublicKey, PRIVATE_KEY_SIZE};
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        inputs.push(rand_input_vector(PRIVATE_KEY_SIZE, rng));

        if rng.gen::<bool>() {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }
    }

    for (class, k) in classes.into_iter().zip(inputs.into_iter()) {
        let sk = PrivateKey::from_slice(&k).unwrap_or(PrivateKey::generate());
        runner.run_one(class, || PublicKey::try_from(&sk).unwrap());
    }
}

fn test_x25519_scalarmul(runner: &mut CtRunner, rng: &mut BenchRng) {
    use orion::hazardous::ecc::x25519::{PrivateKey, PublicKey, PRIVATE_KEY_SIZE};
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        inputs.push(rand_input_vector(PRIVATE_KEY_SIZE, rng));

        if rng.gen::<bool>() {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }
    }

    for (class, k) in classes.into_iter().zip(inputs.into_iter()) {
        let sk = PrivateKey::from_slice(&k).unwrap_or(PrivateKey::generate());
        let pk_other = PublicKey::try_from(&PrivateKey::generate()).unwrap();

        runner.run_one(class, || key_agreement(&sk, &pk_other).unwrap());
    }
}

// src: https://github.com/orion-rs/orion/blob/master/src/hazardous/kem/ml_kem/internal/fe.rs
const KYBER_Q: u32 = 3329;

fn conditional_sub_u32(a: u32) -> u32 {
    // Calculate a - mod
    let t: u32 = a.overflowing_sub(KYBER_Q).0;

    // Check if a >= mod (if t is non-negative)
    // If a >= mod, mask will be 0xFFFFFFF, otherwise 0
    let mask: u32 = 0u32.overflowing_sub(t >> 31).0;

    // If mask is 0, return a (no subtraction), otherwise return t (a - mod)
    (t & !mask) | (a & mask)
}

fn barrett_reduce(value: u32) -> u32 {
    debug_assert!(value < KYBER_Q.pow(2));

    const MUL: u64 = 5039;
    const SHIFT: u64 = 24;

    let quo: u32 = ((u64::from(value) * MUL) >> SHIFT) as u32;
    let r = value - (quo * KYBER_Q);
    // NOTE: Guaranteed now 0 <= r < 2q. This is where we add the
    // conditional subtraction.
    debug_assert!((0..KYBER_Q * 2).contains(&r));

    let ret = conditional_sub_u32(r);
    debug_assert!((0..KYBER_Q).contains(&ret));

    ret
}

fn test_mlkem_barrett_reduce(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<u32> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        // "Given value < 2q return value mod q (in [0, n])."
        inputs.push(rng.gen_range(0..(KYBER_Q * KYBER_Q)));

        if rng.gen::<bool>() {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }
    }

    for (class, k) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || barrett_reduce(k));
    }
}

// src: https://github.com/orion-rs/orion/blob/master/src/hazardous/kem/ml_kem/internal/fe.rs
fn decompress(y: u32, d: u8) -> u32 {
    debug_assert!((1..=11).contains(&d));

    let div: u32 = y * KYBER_Q;
    let mut quo: u32 = div >> d as u32;
    quo += (div >> (d as u32 - 1)) & 1;

    debug_assert!(quo < KYBER_Q);

    quo
}

fn compress(fe: u32, d: u8) -> u32 {
    debug_assert!((1..=11).contains(&d));

    const MUL: u64 = 5039;
    const SHIFT: u64 = 24;

    let div: u32 = fe << d;
    let mut quo: u32 = ((u64::from(div) * MUL) >> SHIFT) as u32;
    let rem: u32 = div - (quo * KYBER_Q);

    quo += ((KYBER_Q / 2).overflowing_sub(rem).0 >> 31) & 1;
    quo += ((KYBER_Q + KYBER_Q / 2 - rem) >> 31) & 1;

    let mask: u32 = (1 << d as u32) - 1;

    ((quo & mask) as u16) as u32
}

fn test_compress<const D: u8>(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<u32> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        inputs.push(rng.gen_range(0..2u32.pow(D as u32)));

        if rng.gen::<bool>() {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || compress(decompress(x, D), D));
    }
}

fn test_compress_d1(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_compress::<1u8>(runner, rng);
}

fn test_compress_d4(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_compress::<4u8>(runner, rng);
}

fn test_compress_d5(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_compress::<5u8>(runner, rng);
}

fn test_compress_d6(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_compress::<6u8>(runner, rng);
}

fn test_compress_d10(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_compress::<10u8>(runner, rng);
}

fn test_compress_d11(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_compress::<11u8>(runner, rng);
}

ctbench_main!(
    test_newtype,
    test_newtype_slice,
    test_secure_cmp,
    test_poly1305,
    test_poly1305_verify,
    test_ct_base64_encode,
    test_ct_base64_decode,
    test_x25519_scalarmul_base,
    test_x25519_scalarmul,
    test_mlkem_barrett_reduce,
    test_compress_d1,
    test_compress_d4,
    test_compress_d5,
    test_compress_d6,
    test_compress_d10,
    test_compress_d11
);
