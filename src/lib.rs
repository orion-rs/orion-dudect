/// Number of testing samples to generate.
pub const NUMBER_OF_SAMPLES: usize = 100_000_0;

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
            let re = Regex::new(r"(max t = )[+-]\d{0,5}.\d{0,5}").unwrap();
            for cap in re.captures_iter(&line) {
                let (_, tval) = &cap[0].split_at(8); // Splits before a "+" or "-"
                // For debugging
                println!("Read: max t: {}", tval);
                
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
                    // max t must be in range of -5..5.
                    assert!(*t_value <= 5f64);
                    assert!(*t_value >= -5f64);
                }
            }
		};
	}

    dudect_test_results!(dudect_secure_cmp, "secure_cmp");
    dudect_test_results!(dudect_poly1305, "poly1305");
}
