#[macro_use]
extern crate dudect_bencher;
extern crate orion;
extern crate rand;
extern crate orion_dudect;

use rand::{Rng, RngCore};
use dudect_bencher::{BenchRng, Class, CtRunner};
use orion::hazardous::mac::poly1305;
use orion::hazardous::constants::POLY1305_KEYSIZE;
use orion_dudect::NUMBER_OF_SAMPLES;

// Return a random vector of length len
fn rand_vec(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut arr = vec![0u8; len];
    rng.fill_bytes(&mut arr);
    arr
}

// Based on `dudect-bencher`s examples.
fn test_poly1305(runner: &mut CtRunner, rng: &mut BenchRng) {
    // The length of input vectors.
    let vlen = POLY1305_KEYSIZE;
    
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
        // u will be used as SecretKey and v as message to be authenticated.
        let sk = poly1305::OneTimeKey::from_slice(&u[..]).unwrap();
        runner.run_one(class, || poly1305::poly1305(&sk, &v[..]).unwrap());
    }
}

ctbench_main!(test_poly1305);
