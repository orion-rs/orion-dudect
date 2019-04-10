for file in ct-bencher/*[.rs];
    do  
        mkdir bench-results;
        filename=$(basename "$file");
        fname="${filename%.*}"; # Filename without .rs extension
        cargo run --release --bin $fname > bench-results/$fname.txt;
    done
