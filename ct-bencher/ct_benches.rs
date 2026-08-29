#[macro_use]
extern crate dudect_bencher;
extern crate ct_codecs;
extern crate orion;
extern crate orion_dudect;
extern crate rand;

use std::convert::TryFrom;

use dudect_bencher::{BenchRng, Class, CtRunner};
use orion::KP;
use orion::hazardous::ecc::x25519::key_agreement;
use orion::hazardous::mac::poly1305::{OneTimeKey, POLY1305_KEYSIZE, Poly1305};
use orion::hazardous::stream::chacha20::{CHACHA_KEYSIZE, SecretKey};
use orion::pwhash::PWHASH_LENGTH;
use orion::util::secure_cmp;
use orion_dudect::{NUMBER_OF_SAMPLES, generate_input_classes, rand_input_vector};
// `Base64NoPadding` is the padding used in orion::pwhash::PasswordHash
use crate::rand::RngExt;
use ct_codecs::{Base64NoPadding, Decoder, Encoder};

use orion::hazardous::dsa::{
    FieldElement, MlDsa44, MlDsa65, MlDsa87, MlDsaParameters, Standard, mldsa44, mldsa65, mldsa87,
    montgomery_reduce,
};
use orion::hazardous::kem::{FieldElement as MlKemFieldElement, barrett_reduce};

// We only test one newtype that implements PartialEq, because they
// all use the macro to implement it.
fn test_newtype(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, CHACHA_KEYSIZE);

    for (class, (u, v)) in classes.into_iter().zip(inputs) {
        let sk0 = SecretKey::try_from(&u[..]).unwrap();
        let sk1 = SecretKey::try_from(&v[..]).unwrap();
        runner.run_one(class, || sk0 == sk1);
    }
}

// We only test one newtype that implements PartialEq, because they
// all use the macro to implement it.
fn test_newtype_slice(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, CHACHA_KEYSIZE);

    for (class, (u, v)) in classes.into_iter().zip(inputs) {
        let sk0 = SecretKey::try_from(&u[..]).unwrap();
        runner.run_one(class, || sk0 == v[..]);
    }
}

fn test_secure_cmp(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, 32);

    for (class, (u, v)) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || secure_cmp(&u[..], &v[..]).is_ok());
    }
}

fn test_poly1305(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, POLY1305_KEYSIZE);

    for (class, (u, v)) in classes.into_iter().zip(inputs) {
        // u will be used as SecretKey and v as message to be authenticated.
        let sk = OneTimeKey::try_from(&u[..]).unwrap();
        runner.run_one(class, || Poly1305::poly1305(&sk, &v[..]).unwrap());
    }
}

fn test_poly1305_verify(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, POLY1305_KEYSIZE);

    for (class, (u, v)) in classes.into_iter().zip(inputs) {
        // u will be used as SecretKey and v as message to be authenticated.
        let sk = OneTimeKey::try_from(&u[..]).unwrap();
        let expected = Poly1305::poly1305(&sk, &v[..]).unwrap();

        runner.run_one(class, || Poly1305::verify(&expected, &sk, &v[..]).is_ok());
    }
}

fn test_ct_base64_encode(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, PWHASH_LENGTH);

    for (class, (u, _v)) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || Base64NoPadding::encode_to_string(&u[..]).unwrap());
    }
}

fn test_ct_base64_decode(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, PWHASH_LENGTH);

    for (class, (u, _v)) in classes.into_iter().zip(inputs) {
        let encoded = Base64NoPadding::encode_to_string(&u[..]).unwrap();

        runner.run_one(class, || {
            Base64NoPadding::decode_to_vec(encoded.as_str(), None).unwrap()
        });
    }
}

fn test_x25519_scalarmul_base(runner: &mut CtRunner, rng: &mut BenchRng) {
    use orion::hazardous::ecc::x25519::{PRIVATE_KEY_SIZE, PrivateKey, PublicKey};
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(vec![0u8; PRIVATE_KEY_SIZE]);
            classes.push(Class::Left);
        } else {
            inputs.push(rand_input_vector(PRIVATE_KEY_SIZE, rng));
            classes.push(Class::Right);
        }
    }

    for (class, k) in classes.into_iter().zip(inputs) {
        let sk = PrivateKey::try_from(&k).unwrap();
        runner.run_one(class, || PublicKey::try_from(&sk).unwrap());
    }
}

fn test_x25519_scalarmul(runner: &mut CtRunner, rng: &mut BenchRng) {
    use orion::hazardous::ecc::x25519::{PRIVATE_KEY_SIZE, PrivateKey, PublicKey};
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(vec![0u8; PRIVATE_KEY_SIZE]);
            classes.push(Class::Left);
        } else {
            inputs.push(rand_input_vector(PRIVATE_KEY_SIZE, rng));
            classes.push(Class::Right);
        }
    }

    let pk_other = PublicKey::try_from(&PrivateKey::generate().unwrap()).unwrap();

    for (class, k) in classes.into_iter().zip(inputs) {
        let sk = PrivateKey::try_from(&k).unwrap();
        runner.run_one(class, || key_agreement(&sk, &pk_other).unwrap());
    }
}

const KYBER_Q: u32 = 3329;

fn test_mlkem_barrett_reduce(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<u32> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push((KYBER_Q * 2) - 1);
            classes.push(Class::Left);
        } else {
            // "Given value < 2q return value mod q (in [0, n])."
            inputs.push(rng.random_range(0..(KYBER_Q * KYBER_Q)));
            classes.push(Class::Right);
        }
    }

    for (class, k) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || barrett_reduce(*k));
    }
}

fn test_compress<const D: u8>(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<MlKemFieldElement> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(MlKemFieldElement::new(KYBER_Q - 1));
            classes.push(Class::Left);
        } else {
            inputs.push(MlKemFieldElement::new(
                rng.random_range(0..2u32.pow(D as u32)),
            ));
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || MlKemFieldElement::decompress(x.compress(D), D));
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

fn test_sk_decode_mldsa44(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    let fixed = mldsa44::KeyPair::new(seed.into())
        .unwrap()
        .private()
        .unprotected_as_ref()
        .to_vec();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(fixed.clone());
            classes.push(Class::Left);
        } else {
            rng.fill(&mut seed);
            inputs.push(
                mldsa44::KeyPair::new(seed.into())
                    .unwrap()
                    .private()
                    .unprotected_as_ref()
                    .to_vec(),
            );
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || {
            MlDsa44::sk_decode::<{ MlDsa44::DIM_K }, { MlDsa44::DIM_L }>(x).unwrap()
        });
    }
}

fn test_sk_decode_mldsa65(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    let fixed = mldsa65::KeyPair::new(seed.into())
        .unwrap()
        .private()
        .unprotected_as_ref()
        .to_vec();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(fixed.clone());
            classes.push(Class::Left);
        } else {
            rng.fill(&mut seed);
            inputs.push(
                mldsa65::KeyPair::new(seed.into())
                    .unwrap()
                    .private()
                    .unprotected_as_ref()
                    .to_vec(),
            );
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || {
            MlDsa65::sk_decode::<{ MlDsa65::DIM_K }, { MlDsa65::DIM_L }>(x).unwrap()
        });
    }
}

fn test_sk_decode_mldsa87(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    let fixed = mldsa87::KeyPair::new(seed.into())
        .unwrap()
        .private()
        .unprotected_as_ref()
        .to_vec();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(fixed.clone());
            classes.push(Class::Left);
        } else {
            rng.fill(&mut seed);
            inputs.push(
                mldsa87::KeyPair::new(seed.into())
                    .unwrap()
                    .private()
                    .unprotected_as_ref()
                    .to_vec(),
            );
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || {
            MlDsa87::sk_decode::<{ MlDsa87::DIM_K }, { MlDsa87::DIM_L }>(x).unwrap()
        });
    }
}

fn test_power2round<P: MlDsaParameters>(runner: &mut CtRunner, rng: &mut BenchRng) {
    const DILITHIUM_Q: u32 = 8380417;

    let mut inputs: Vec<FieldElement<Standard>> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(FieldElement::<Standard>::new(DILITHIUM_Q - 1));
            classes.push(Class::Left);
        } else {
            inputs.push(FieldElement::<Standard>::new(
                rng.random_range(0..DILITHIUM_Q),
            ));
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || x.power2round::<P>());
    }
}

fn test_power2round_mldsa44(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_power2round::<MlDsa44>(runner, rng);
}

fn test_power2round_mldsa65(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_power2round::<MlDsa65>(runner, rng);
}

fn test_power2round_mldsa87(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_power2round::<MlDsa87>(runner, rng);
}

fn test_montgomery_reduce(runner: &mut CtRunner, rng: &mut BenchRng) {
    const DILITHIUM_Q: u32 = 8380417;

    let mut inputs: Vec<u64> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(0);
            classes.push(Class::Left);
        } else {
            inputs.push(rng.random_range(0..=(DILITHIUM_Q as u64 - 1) * 2));
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || montgomery_reduce(*x));
    }
}

fn test_decompose<P: MlDsaParameters>(runner: &mut CtRunner, rng: &mut BenchRng) {
    const DILITHIUM_Q: u32 = 8380417;

    let mut inputs: Vec<FieldElement<Standard>> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(FieldElement::<Standard>::new(DILITHIUM_Q - 1));
            classes.push(Class::Left);
        } else {
            inputs.push(FieldElement::<Standard>::new(
                rng.random_range(0..DILITHIUM_Q),
            ));
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || x.decompose::<P>());
    }
}

fn test_decompose_mldsa44(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_decompose::<MlDsa44>(runner, rng);
}

fn test_decompose_mldsa65(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_decompose::<MlDsa65>(runner, rng);
}

fn test_decompose_mldsa87(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_decompose::<MlDsa87>(runner, rng);
}

fn test_is_outside_bound<P: MlDsaParameters>(runner: &mut CtRunner, rng: &mut BenchRng) {
    const DILITHIUM_Q: u32 = 8380417;

    let mut inputs: Vec<FieldElement<Standard>> = Vec::new();
    let mut classes: Vec<Class> = Vec::new();

    // The `bound` is a public parameter that depends on the ML-DSA
    // parameterset. So that has to stay fixed, not the value of the
    // field element.
    let bound = P::ETA as u32 + 1;

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.random::<bool>() {
            inputs.push(FieldElement::<Standard>::new(DILITHIUM_Q - 1));
            classes.push(Class::Left);
        } else {
            inputs.push(FieldElement::<Standard>::new(
                rng.random_range(0..DILITHIUM_Q),
            ));
            classes.push(Class::Right);
        }
    }

    for (class, x) in classes.into_iter().zip(inputs.iter()) {
        runner.run_one(class, || x.is_outside_bound(bound));
    }
}

fn test_is_outside_bound_mldsa44(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_is_outside_bound::<MlDsa44>(runner, rng);
}

fn test_is_outside_bound_mldsa65(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_is_outside_bound::<MlDsa65>(runner, rng);
}

fn test_is_outside_bound_mldsa87(runner: &mut CtRunner, rng: &mut BenchRng) {
    test_is_outside_bound::<MlDsa87>(runner, rng);
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
    test_compress_d11,
    test_sk_decode_mldsa44,
    test_sk_decode_mldsa65,
    test_sk_decode_mldsa87,
    test_power2round_mldsa44,
    test_power2round_mldsa65,
    test_power2round_mldsa87,
    test_montgomery_reduce,
    test_decompose_mldsa44,
    test_decompose_mldsa65,
    test_decompose_mldsa87,
    test_is_outside_bound_mldsa44,
    test_is_outside_bound_mldsa65,
    test_is_outside_bound_mldsa87
);
