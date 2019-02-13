#[macro_use]
extern crate dudect_bencher;
extern crate orion;
extern crate rand;

use dudect_bencher::{BenchRng, Class, CtRunner};
use orion::util::secure_cmp;
use rand::Rng;

// Return a random vector of length len
fn rand_vec(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut arr = vec![0u8; len];
    rng.fill_bytes(&mut arr);
    arr
}

// Based on `dudect-bencher`s examples.
fn test_secure_cmp(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Make vectors of size 100
    let vlen = 100;
    let mut inputs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut classes = Vec::new();

    // Make 100,000 random pairs of vectors
    for _ in 0..100_000 {
        // Flip a coin. If true, make a pair of vectors that are equal to each other and put it
        // in the Left distribution
        if rng.gen::<bool>() {
            let v1 = rand_vec(vlen, rng);
            let v2 = v1.clone();
            inputs.push((v1, v2));
            classes.push(Class::Left);
        }
        // Otherwise, make a pair of vectors that differ at the 6th element and put it in the
        // right distribution
        else {
            let v1 = rand_vec(vlen, rng);
            let mut v2 = v1.clone();
            v2[5] = 7;
            inputs.push((v1, v2));
            classes.push(Class::Right);
        }
    }

    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        // Now time how long it takes to do a vector comparison
        runner.run_one(class, || secure_cmp(&u[..], &v[..]));
    }
}

ctbench_main!(test_secure_cmp);
