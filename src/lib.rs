use dudect_bencher::{BenchRng, Class};
use rand::{Rng, RngCore};

/// Number of testing samples to generate.
pub const NUMBER_OF_SAMPLES: usize = 1_000_000;
/// Input format for dudect.
pub type DudectInput = Vec<(Vec<u8>, Vec<u8>)>;

// Return a random input vector.
pub fn rand_input_vector(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut arr = vec![0u8; len];
    rng.fill_bytes(&mut arr);
    arr
}

/// Generate dudect input classes.
pub fn generate_input_classes(rng: &mut BenchRng, input_len: usize) -> (DudectInput, Vec<Class>) {
    let mut inputs: DudectInput = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        let v1 = rand_input_vector(input_len, rng);
        if rng.gen::<bool>() {
            let v2 = v1.clone();
            inputs.push((v1, v2));
            classes.push(Class::Left);
        } else {
            let v2 = vec![0u8; v1.len()];
            inputs.push((v1, v2));
            classes.push(Class::Right);
        }
    }

    (inputs, classes)
}

#[cfg(test)]
mod tests {

    extern crate regex;

    use regex::Regex;
    use std::io::BufRead;
    use std::{fs::File, io::BufReader};

    type Measurement = (String, f64, String);

    type NameAndSeed = (String, String);
    type NameAndTValue = (String, f64);

    fn read_bench_out(bench_result_name: &str) -> Vec<Measurement> {
        let file = File::open(format!("./bench-results/{}.txt", bench_result_name)).unwrap();
        let reader = BufReader::new(file);

        let mut all_seed_pairs: Vec<NameAndSeed> = Vec::new();
        let mut all_tval_pairs: Vec<NameAndTValue> = Vec::new();

        for line in reader.lines().filter_map(|result| result.ok()) {
            let re_seed = Regex::new(r"(seeded with )[a-z,0-9,_]+").unwrap();
            let re_result = Regex::new(r"(max t = )[+-]\d{0,5}.\d{0,5}").unwrap();
            let re_name = Regex::new(r"(bench test_)[a-z,0-9,_]+").unwrap();

            for (cap_name, cap_res) in re_name
                .captures_iter(&line)
                .zip(re_result.captures_iter(&line))
            {
                let (_, name) = &cap_name[0].split_at(6); // Splits before a "bench "
                let (_, tval) = &cap_res[0].split_at(8); // Splits before a "+" or "-"
                match tval.parse::<f64>() {
                    Ok(val) => all_tval_pairs.push((name.to_string(), val)),
                    Err(bad_value) => panic!(
                        "Tried to parse invalid float {}. Is the correct file specified?",
                        bad_value
                    ),
                }
            }

            for (cap_name, cap_seed) in re_name
                .captures_iter(&line)
                .zip(re_seed.captures_iter(&line))
            {
                let (_, name) = &cap_name[0].split_at(6); // Splits before a "bench "
                let (_, seed) = &cap_seed[0].split_at(12); // Splits before a " "
                all_seed_pairs.push((name.to_string(), seed.to_string()));
            }
        }

        let mut all_measurements: Vec<Measurement> = Vec::new();
        // Match pairs on name
        for (tval_pair, seed_pair) in all_tval_pairs.iter().zip(all_seed_pairs.iter()) {
            if tval_pair.0 == seed_pair.0 {
                all_measurements.push((
                    tval_pair.0.to_string(), // Name
                    tval_pair.1,             // T-value
                    seed_pair.1.to_string(), // Seed
                ));
            }
        }

        all_measurements
    }

    macro_rules! dudect_test_results {
        ($test_name:ident, $bench_to_read:expr) => {
            #[test]
            fn $test_name() {
                let max_t_measurements = read_bench_out($bench_to_read);
                for measurement in max_t_measurements.iter() {
                    // max t must be in range of -4.5..4.5.
                    let custom_err = format!("dudect test found to break threshold: name: {}, t value: {}, seed: {:?}", measurement.0, measurement.1, measurement.2);
                    assert!(measurement.1 <= 4.5f64, "{}", custom_err);
                    assert!(measurement.1 >= -4.5f64, "{}", custom_err);
                }
            }
        };
    }

    dudect_test_results!(dudect_ct_benches, "ct_benches");
}
