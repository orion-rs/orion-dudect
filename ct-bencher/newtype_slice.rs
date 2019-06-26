#[macro_use]
extern crate dudect_bencher;
extern crate orion;
extern crate rand;
extern crate orion_dudect;

use rand::{Rng, RngCore};
use dudect_bencher::{BenchRng, Class, CtRunner};
use orion::hazardous::stream::chacha20::{CHACHA_KEYSIZE, SecretKey};
use orion_dudect::NUMBER_OF_SAMPLES;

// Return a random vector of length len
fn rand_vec(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut arr = vec![0u8; len];
    rng.fill_bytes(&mut arr);
    arr
}

// Based on `dudect-bencher`s examples.

// We only test one because they all implement PartialEq based on the same macro
// and should therefor be exactly the same.
fn test_newtype(runner: &mut CtRunner, rng: &mut BenchRng) {
    // The length of input vectors.
    let vlen = CHACHA_KEYSIZE;
    
    let mut inputs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.gen::<bool>() {
            let v1 = rand_vec(vlen, rng);
            let v2 = v1.clone();
            inputs.push((v1, v2));
            classes.push(Class::Left);
        }
        else {
            let v1 = rand_vec(vlen, rng);
            let v2 = vec![0u8; v1.len()];
            inputs.push((v1, v2));
            classes.push(Class::Right);
        }
    }

    // Run timing
    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        let sk0 = SecretKey::from_slice(&u[..]).unwrap();
        let sk1 = SecretKey::from_slice(&v[..]).unwrap();
        runner.run_one(class, || sk0 == sk1.unprotected_as_bytes());
    }
}

ctbench_main!(test_newtype);