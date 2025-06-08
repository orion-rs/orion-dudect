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

ctbench_main!(
    test_newtype,
    test_newtype_slice,
    test_secure_cmp,
    test_poly1305,
    test_poly1305_verify,
    test_ct_base64_encode,
    test_ct_base64_decode,
    test_x25519_scalarmul_base,
    test_x25519_scalarmul
);
