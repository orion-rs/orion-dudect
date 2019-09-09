#[macro_use]
extern crate dudect_bencher;
extern crate orion;
extern crate orion_dudect;
extern crate rand;

use dudect_bencher::{BenchRng, CtRunner};
use orion::hazardous::mac::poly1305::{self, POLY1305_KEYSIZE};
use orion_dudect::generate_input_classes;

// Based on `dudect-bencher`s examples.
fn test_poly1305(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, POLY1305_KEYSIZE);

    // Run timing
    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        // u will be used as SecretKey and v as message to be authenticated.
        let sk = poly1305::OneTimeKey::from_slice(&u[..]).unwrap();
        runner.run_one(class, || poly1305::poly1305(&sk, &v[..]).unwrap());
    }
}

ctbench_main!(test_poly1305);
