package magiclink

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

const (
	testSQLiteDBPath = "test_benchmark_sqlite.db"
	testLevelDBPath  = "test_benchmark_leveldb"
)

func setupTestDB(dbType string) (storage.Database, func()) {
	var config storage.Config
	var cleanupPath string

	switch dbType {
	case "sqlite":
		_ = os.Remove(testSQLiteDBPath)
		config = storage.Config{
			Type: "sqlite",
			Path: testSQLiteDBPath,
			Options: map[string]string{
				"journal_mode": "WAL",
				"synchronous":  "NORMAL",
				"cache_size":   "10000",
				"temp_store":   "memory",
			},
		}
		cleanupPath = testSQLiteDBPath
	case "leveldb":
		_ = os.RemoveAll(testLevelDBPath)
		config = storage.Config{
			Type: "leveldb",
			Path: testLevelDBPath,
			Options: map[string]string{
				"block_cache_capacity":  "33554432", // 32MB
				"write_buffer":          "16777216", // 16MB
				"compaction_table_size": "8388608",  // 8MB
			},
		}
		cleanupPath = testLevelDBPath
	default:
		log.Fatalf("Unsupported database type: %s", dbType)
	}

	factory := storage.NewFactory()
	database, err := factory.Create(config)
	if err != nil {
		log.Fatalf("Failed to create test database: %v", err)
	}

	if err := database.Init(); err != nil {
		log.Fatalf("Failed to initialize test database: %v", err)
	}

	cleanup := func() {
		_ = database.Close()
		if dbType == "sqlite" {
			_ = os.Remove(cleanupPath)
		} else {
			_ = os.RemoveAll(cleanupPath)
		}
	}

	return database, cleanup
}

// BenchmarkTokenGeneration_SQLite tests token generation performance with SQLite
func BenchmarkTokenGeneration_SQLite(b *testing.B) {
	benchmarkTokenGeneration(b, "sqlite")
}

// BenchmarkTokenGeneration_LevelDB tests token generation performance with LevelDB
func BenchmarkTokenGeneration_LevelDB(b *testing.B) {
	benchmarkTokenGeneration(b, "leveldb")
}

func benchmarkTokenGeneration(b *testing.B, dbType string) {
	database, cleanup := setupTestDB(dbType)
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

// BenchmarkTokenValidation_SQLite tests token validation performance with SQLite
func BenchmarkTokenValidation_SQLite(b *testing.B) {
	benchmarkTokenValidation(b, "sqlite")
}

// BenchmarkTokenValidation_LevelDB tests token validation performance with LevelDB
func BenchmarkTokenValidation_LevelDB(b *testing.B) {
	benchmarkTokenValidation(b, "leveldb")
}

func benchmarkTokenValidation(b *testing.B, dbType string) {
	database, cleanup := setupTestDB(dbType)
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

// TestLoadTest_SQLite simulates concurrent load on the SQLite token system
func TestLoadTest_SQLite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	testLoadTest(t, "sqlite")
}

// TestLoadTest_LevelDB simulates concurrent load on the LevelDB token system
func TestLoadTest_LevelDB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	testLoadTest(t, "leveldb")
}

func testLoadTest(t *testing.T, dbType string) {
	database, cleanup := setupTestDB(dbType)
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
		t.Run(fmt.Sprintf("%s_%s", scenario.name, dbType), func(t *testing.T) {
			runLoadTest(t, tokenManager, scenario.concurrency, scenario.duration, scenario.operations, dbType)
		})
	}
}

func runLoadTest(t *testing.T, tokenManager *token.Manager, concurrency int, _ time.Duration, totalOps int, dbType string) {
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
					tokenValue, err := tokenManager.Generate(email)
					if err != nil {
						atomic.AddInt64(&errorCount, 1)
						continue
					}

					_, valErr := tokenManager.Validate(tokenValue)
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
	t.Logf("\n=== Load Test Results (%s) ===", dbType)
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

// TestConcurrentAccess_SQLite tests database locking behavior under high concurrency with SQLite
func TestConcurrentAccess_SQLite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent access test in short mode")
	}
	testConcurrentAccess(t, "sqlite")
}

// TestConcurrentAccess_LevelDB tests database locking behavior under high concurrency with LevelDB
func TestConcurrentAccess_LevelDB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent access test in short mode")
	}
	testConcurrentAccess(t, "leveldb")
}

func testConcurrentAccess(t *testing.T, dbType string) {
	database, cleanup := setupTestDB(dbType)
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

	t.Logf("\n=== Concurrent Access Results (%s) ===", dbType)
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
