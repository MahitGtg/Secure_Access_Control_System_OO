#!/bin/bash
# run_fuzzers.sh
set -e

# Set default fuzzing time (5 minutes per target)
export FUZZ_TIME=${FUZZ_TIME:-300}
echo "Fuzzing each target for $FUZZ_TIME seconds"

# Build all fuzzing targets
make fuzz

# Run all fuzzers
make run-fuzz

# Check for crashes
if find test/fuzz/output -name "crash-*" | grep -q .; then
  echo "⚠️ CRASHES DETECTED during fuzzing!"
  find test/fuzz/output -name "crash-*" -exec ls -la {} \;
  echo "To reproduce a crash, run: ./build/fuzz/fuzz_TARGET crash_file"
  exit 1
else
  echo "✅ No crashes detected during fuzzing."
fi

echo "Fuzzing complete. Results are in test/fuzz/output/"