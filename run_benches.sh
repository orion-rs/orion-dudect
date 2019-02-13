for file in ct-bencher/*[.rs];
    do  
        filename=$(basename "$file");
        fname="${filename%.*}"; # Filename without .rs extension
        cargo run --bin $fname > bench-results/$fname.txt;
    done
