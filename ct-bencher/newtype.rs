#[macro_use]
extern crate dudect_bencher;
extern crate orion;
extern crate orion_dudect;
extern crate rand;

use dudect_bencher::{BenchRng, CtRunner};
use orion::hazardous::stream::chacha20::{SecretKey, CHACHA_KEYSIZE};
use orion_dudect::generate_input_classes;

// We only test one because they all implement PartialEq based on the same macro
// and should therefor be exactly the same.
fn test_newtype(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, CHACHA_KEYSIZE);

    // Run timing
    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        let sk0 = SecretKey::from_slice(&u[..]).unwrap();
        let sk1 = SecretKey::from_slice(&v[..]).unwrap();
        runner.run_one(class, || sk0 == sk1);
    }
}

ctbench_main!(test_newtype);
