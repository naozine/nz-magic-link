package magiclink

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/naozine/nz-magic-link/magiclink/internal/db"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

const (
	testDBPath = "test_benchmark.db"
)

func setupTestDB() (*db.DB, func()) {
	// Remove existing test database
	os.Remove(testDBPath)

	database, err := db.New(testDBPath)
	if err != nil {
		log.Fatalf("Failed to create test database: %v", err)
	}

	if err := database.Init(); err != nil {
		log.Fatalf("Failed to initialize test database: %v", err)
	}

	cleanup := func() {
		database.Close()
		os.Remove(testDBPath)
	}

	return database, cleanup
}

// BenchmarkTokenGeneration tests token generation performance
func BenchmarkTokenGeneration(b *testing.B) {
	database, cleanup := setupTestDB()
	defer cleanup()

	tokenManager := token.New(database, 15*time.Minute)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			email := fmt.Sprintf("user%d@example.com", counter)
			_, err := tokenManager.Generate(email)
			if err != nil {
				b.Errorf("Failed to generate token: %v", err)
			}
			counter++
		}
	})
}

// BenchmarkTokenValidation tests token validation performance
func BenchmarkTokenValidation(b *testing.B) {
	database, cleanup := setupTestDB()
	defer cleanup()

	tokenManager := token.New(database, 15*time.Minute)

	// Pre-generate tokens for validation
	tokens := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		email := fmt.Sprintf("user%d@example.com", i)
		generatedToken, err := tokenManager.Generate(email)
		if err != nil {
			b.Fatalf("Failed to generate token for benchmark: %v", err)
		}
		tokens[i] = generatedToken
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			if counter >= len(tokens) {
				counter = 0
			}
			_, _ = tokenManager.Validate(tokens[counter])
			// Note: This will fail after first use, but we're measuring DB performance
			counter++
		}
	})
}

// LoadTest simulates concurrent load on the token system
func TestLoadTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	database, cleanup := setupTestDB()
	defer cleanup()

	tokenManager := token.New(database, 15*time.Minute)

	// Test scenarios
	scenarios := []struct {
		name        string
		concurrency int
		duration    time.Duration
		operations  int
	}{
		{"Low Load", 10, 10 * time.Second, 100},
		{"Medium Load", 50, 10 * time.Second, 500},
		{"High Load", 100, 10 * time.Second, 1000},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			runLoadTest(t, tokenManager, scenario.concurrency, scenario.duration, scenario.operations)
		})
	}
}

func runLoadTest(t *testing.T, tokenManager *token.Manager, concurrency int, duration time.Duration, totalOps int) {
	var (
		successCount int64
		errorCount   int64
		totalLatency int64
		maxLatency   int64
		minLatency   int64 = 1000000000 // 1 second in nanoseconds
	)

	start := time.Now()
	var wg sync.WaitGroup

	// Channel to control operation rate
	opsChan := make(chan int, totalOps)
	for i := 0; i < totalOps; i++ {
		opsChan <- i
	}
	close(opsChan)

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for opID := range opsChan {
				opStart := time.Now()

				// Alternate between generation and validation
				if opID%2 == 0 {
					// Generate token
					email := fmt.Sprintf("worker%d_op%d@example.com", workerID, opID)
					_, err := tokenManager.Generate(email)
					if err != nil {
						atomic.AddInt64(&errorCount, 1)
						t.Logf("Generation error: %v", err)
					} else {
						atomic.AddInt64(&successCount, 1)
					}
				} else {
					// For validation, we need a pre-existing token
					// Generate one on the fly for simplicity
					email := fmt.Sprintf("validate%d_op%d@example.com", workerID, opID)
					token, err := tokenManager.Generate(email)
					if err != nil {
						atomic.AddInt64(&errorCount, 1)
						continue
					}

					_, valErr := tokenManager.Validate(token)
					if valErr != nil {
						atomic.AddInt64(&errorCount, 1)
						t.Logf("Validation error: %v", valErr)
					} else {
						atomic.AddInt64(&successCount, 1)
					}
				}

				// Record latency
				latency := time.Since(opStart).Nanoseconds()
				atomic.AddInt64(&totalLatency, latency)

				// Update min/max latency
				for {
					current := atomic.LoadInt64(&maxLatency)
					if latency <= current || atomic.CompareAndSwapInt64(&maxLatency, current, latency) {
						break
					}
				}
				for {
					current := atomic.LoadInt64(&minLatency)
					if latency >= current || atomic.CompareAndSwapInt64(&minLatency, current, latency) {
						break
					}
				}
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Calculate metrics
	totalOpsExecuted := atomic.LoadInt64(&successCount) + atomic.LoadInt64(&errorCount)
	avgLatency := atomic.LoadInt64(&totalLatency) / totalOpsExecuted
	throughput := float64(totalOpsExecuted) / elapsed.Seconds()
	errorRate := float64(atomic.LoadInt64(&errorCount)) / float64(totalOpsExecuted) * 100

	// Report results
	t.Logf("\n=== Load Test Results ===")
	t.Logf("Concurrency: %d goroutines", concurrency)
	t.Logf("Duration: %v", elapsed)
	t.Logf("Total Operations: %d", totalOpsExecuted)
	t.Logf("Successful Operations: %d", atomic.LoadInt64(&successCount))
	t.Logf("Failed Operations: %d", atomic.LoadInt64(&errorCount))
	t.Logf("Error Rate: %.2f%%", errorRate)
	t.Logf("Throughput: %.2f ops/sec", throughput)
	t.Logf("Average Latency: %.2f ms", float64(avgLatency)/1000000)
	t.Logf("Min Latency: %.2f ms", float64(atomic.LoadInt64(&minLatency))/1000000)
	t.Logf("Max Latency: %.2f ms", float64(atomic.LoadInt64(&maxLatency))/1000000)
}

// TestConcurrentAccess tests database locking behavior under high concurrency
func TestConcurrentAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent access test in short mode")
	}

	database, cleanup := setupTestDB()
	defer cleanup()

	tokenManager := token.New(database, 15*time.Minute)

	concurrency := 200
	operationsPerWorker := 10

	var wg sync.WaitGroup
	var lockErrors int64
	var timeoutErrors int64
	var otherErrors int64

	start := time.Now()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < operationsPerWorker; j++ {
				email := fmt.Sprintf("concurrent%d_%d@example.com", workerID, j)
				_, err := tokenManager.Generate(email)

				if err != nil {
					errStr := err.Error()
					if contains(errStr, "database is locked") {
						atomic.AddInt64(&lockErrors, 1)
					} else if contains(errStr, "timeout") {
						atomic.AddInt64(&timeoutErrors, 1)
					} else {
						atomic.AddInt64(&otherErrors, 1)
						t.Logf("Unexpected error: %v", err)
					}
				}
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalOperations := int64(concurrency * operationsPerWorker)
	totalErrors := atomic.LoadInt64(&lockErrors) + atomic.LoadInt64(&timeoutErrors) + atomic.LoadInt64(&otherErrors)

	t.Logf("\n=== Concurrent Access Results ===")
	t.Logf("Concurrency: %d goroutines", concurrency)
	t.Logf("Operations per worker: %d", operationsPerWorker)
	t.Logf("Total operations: %d", totalOperations)
	t.Logf("Duration: %v", elapsed)
	t.Logf("Lock errors: %d", atomic.LoadInt64(&lockErrors))
	t.Logf("Timeout errors: %d", atomic.LoadInt64(&timeoutErrors))
	t.Logf("Other errors: %d", atomic.LoadInt64(&otherErrors))
	t.Logf("Total errors: %d", totalErrors)
	t.Logf("Success rate: %.2f%%", float64(totalOperations-totalErrors)/float64(totalOperations)*100)
	t.Logf("Throughput: %.2f ops/sec", float64(totalOperations)/elapsed.Seconds())
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsHelper(s, substr))))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
