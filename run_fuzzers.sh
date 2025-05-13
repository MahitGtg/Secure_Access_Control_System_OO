#!/bin/bash
# run_fuzzers.sh
set -e  # Exit on any error

# Set default fuzzing time (5 minutes per target)
export FUZZ_TIME=${FUZZ_TIME:-20}
echo "Fuzzing each target for $FUZZ_TIME seconds"

# Create necessary directories
mkdir -p test/fuzz/corpus/{account,login,password}
mkdir -p test/fuzz/output/{account,login,password}

# Build all fuzzing targets
echo "Building fuzzing targets..."
make fuzz

# Run all fuzzers
echo "Starting fuzzing session..."
make run-fuzz

# Check for crashes
if find test/fuzz/output -name "crash-*" | grep -q .; then
    echo "⚠️  CRASHES DETECTED during fuzzing!"
    echo "Found crash files:"
    find test/fuzz/output -name "crash-*" -exec ls -la {} \;
    echo ""
    echo "To reproduce a crash, run: ./build/fuzz/fuzz_TARGET crash_file"
    echo "For example: ./build/fuzz/fuzz_password test/fuzz/output/password/crash-*"
    exit 1
else
    echo "✅ No crashes detected during fuzzing."
fi

# Print summary
echo ""
echo "Fuzzing complete. Results are in test/fuzz/output/"
echo "Corpus files are in test/fuzz/corpus/"
echo ""
echo "To run a longer fuzzing session, use:"
echo "  FUZZ_TIME=600 ./run_fuzzers.sh  # 10 minutes per fuzzer"
echo "  FUZZ_TIME=1800 ./run_fuzzers.sh  # 30 minutes per fuzzer" 