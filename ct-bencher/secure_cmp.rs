#[macro_use]
extern crate dudect_bencher;
extern crate orion;
extern crate orion_dudect;
extern crate rand;

use dudect_bencher::{BenchRng, CtRunner};
use orion::util::secure_cmp;
use orion_dudect::generate_input_classes;

// Based on `dudect-bencher`s examples.
fn test_secure_cmp(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (inputs, classes) = generate_input_classes(rng, 32);

    // Run timing
    for (class, (u, v)) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || secure_cmp(&u[..], &v[..]).is_ok());
    }
}

ctbench_main!(test_secure_cmp);
