use dudect_bencher::{BenchRng, Class};
use rand::{Rng, RngCore};

/// Number of testing samples to generate.
pub const NUMBER_OF_SAMPLES: usize = 1_000_000;
/// Input format for dudect.
pub type DudectInput = Vec<(Vec<u8>, Vec<u8>)>;  

// Return a random input vector.
fn rand_input_vector(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut arr = vec![0u8; len];
    rng.fill_bytes(&mut arr);
    arr
}

/// Generate dudect input classes.
pub fn generate_input_classes(
    rng: &mut BenchRng,
    input_len: usize,
) -> (DudectInput, Vec<Class>) {
    let mut inputs: DudectInput = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..NUMBER_OF_SAMPLES {
        if rng.gen::<bool>() {
            let v1 = rand_input_vector(input_len, rng);
            let v2 = v1.clone();
            inputs.push((v1, v2));
            classes.push(Class::Left);
        } else {
            let v1 = rand_input_vector(input_len, rng);
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

    fn read_bench_out(bench_result_name: &str) -> Vec<f64> {
        let file = File::open(format!("./bench-results/{}.txt", bench_result_name)).unwrap();
        let reader = BufReader::new(file);
        let mut t_values: Vec<f64> = vec![0f64; 0];

        for line in reader.lines().filter_map(|result| result.ok()) {
            // Match a bench max t output here
            let re_name = Regex::new(r"(bench test_)[a-z,0-9,_]+").unwrap();
            let re_result = Regex::new(r"(max t = )[+-]\d{0,5}.\d{0,5}").unwrap();
            for (cap_name, cap_res) in re_name
                .captures_iter(&line)
                .zip(re_result.captures_iter(&line))
            {
                let (_, bench_name) = &cap_name[0].split_at(6); // Splits before a "bench "
                let (_, tval) = &cap_res[0].split_at(8); // Splits before a "+" or "-"
                println!("[{}] Read: max t: {}", bench_name, tval);

                let parsed = &tval.parse::<f64>();
                match parsed {
                    Ok(val) => t_values.push(*val),
                    Err(bad_value) => panic!(
                        "Tried to parse invalid float {}. Is the correct file specified?",
                        bad_value
                    ),
                }
            }
        }

        t_values
    }

    macro_rules! dudect_test_results {
        ($test_name:ident, $bench_to_read:expr) => {
            #[test]
            fn $test_name() {
                let max_t_measurements = read_bench_out($bench_to_read);
                for t_value in max_t_measurements.iter() {
                    // max t must be in range of -4.5..4.5.
                    assert!(*t_value <= 4.5f64);
                    assert!(*t_value >= -4.5f64);
                }
            }
        };
    }

    dudect_test_results!(dudect_ct_benches, "ct_benches");
}
