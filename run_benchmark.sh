#!/bin/bash

echo "=== SQLite Token Management Benchmark Tests ==="
echo "Starting at: $(date)"
echo

# Set Go test timeout
export GO_TEST_TIMEOUT="300s"

echo "1. Running basic benchmarks..."
echo "----------------------------------------"
(cd magiclink && go test -bench=BenchmarkTokenGeneration -benchmem -count=3 -timeout=$GO_TEST_TIMEOUT)
echo
(cd magiclink && go test -bench=BenchmarkTokenValidation -benchmem -count=3 -timeout=$GO_TEST_TIMEOUT)
echo

echo "2. Running load tests..."
echo "----------------------------------------"
(cd magiclink && go test -run=TestLoadTest -timeout=$GO_TEST_TIMEOUT -v)
echo

echo "3. Running concurrent access test..."
echo "----------------------------------------"
(cd magiclink && go test -run=TestConcurrentAccess -timeout=$GO_TEST_TIMEOUT -v)
echo

echo "4. Running all benchmarks with CPU profiling..."
echo "----------------------------------------"
(cd magiclink && go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof -timeout=$GO_TEST_TIMEOUT)
echo

echo "Benchmark completed at: $(date)"
echo
echo "Generated profiles:"
echo "- cpu.prof (CPU profile)"
echo "- mem.prof (Memory profile)"
echo
echo "To analyze profiles, run:"
echo "  go tool pprof cpu.prof"
echo "  go tool pprof mem.prof"