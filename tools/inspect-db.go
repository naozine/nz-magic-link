package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run inspect-db.go <path-to-leveldb>")
		fmt.Println("Example: go run inspect-db.go examples/simple/level.db")
		os.Exit(1)
	}

	dbPath := os.Args[1]
	fmt.Printf("Opening LevelDB at: %s\n", dbPath)

	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	fmt.Println("\n=== Scanning LevelDB Keys ===")

	iter := db.NewIterator(nil, nil)
	defer iter.Release()

	credentialCount := 0
	challengeCount := 0
	otherCount := 0

	for iter.Next() {
		key := string(iter.Key())
		value := iter.Value()

		fmt.Printf("\nKey: %s\n", key)

		// Define local structs to avoid internal package dependency
		type PasskeyCredential struct {
			ID              string    `json:"id"`
			UserID          string    `json:"user_id"`
			PublicKey       []byte    `json:"public_key"`
			SignCount       uint32    `json:"sign_count"`
			AAGUID          string    `json:"aaguid,omitempty"`
			AttestationType string    `json:"attestation_type"`
			Transports      []string  `json:"transports"`
			CreatedAt       time.Time `json:"created_at"`
			UpdatedAt       time.Time `json:"updated_at"`
		}

		type PasskeyChallenge struct {
			ID                     string    `json:"id"`
			UserID                 string    `json:"user_id,omitempty"`
			Type                   string    `json:"type"`
			Challenge              string    `json:"challenge"`
			ExpiresAt              time.Time `json:"expires_at"`
			SessionDataJSON        string    `json:"session_data_json"`
			RequestOptionsSnapshot string    `json:"request_options_snapshot"`
		}

		if len(key) > 11 && key[:12] == "credential_" {
			credentialCount++
			fmt.Printf("Type: Passkey Credential\n")

			// Try to parse as PasskeyCredential
			var cred PasskeyCredential
			if err := json.Unmarshal(value, &cred); err == nil {
				fmt.Printf("  - User ID: %s\n", cred.UserID)
				fmt.Printf("  - Credential ID: %s\n", cred.ID)
				fmt.Printf("  - Sign Count: %d\n", cred.SignCount)
				fmt.Printf("  - AAGUID: %s\n", cred.AAGUID)
				fmt.Printf("  - Attestation Type: %s\n", cred.AttestationType)
				fmt.Printf("  - Transports: %v\n", cred.Transports)
				fmt.Printf("  - Created: %s\n", cred.CreatedAt.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Printf("  - Raw data: %s\n", string(value))
			}
		} else if len(key) > 10 && key[:11] == "challenge_" {
			challengeCount++
			fmt.Printf("Type: Passkey Challenge\n")

			// Try to parse as PasskeyChallenge
			var challenge PasskeyChallenge
			if err := json.Unmarshal(value, &challenge); err == nil {
				fmt.Printf("  - Challenge ID: %s\n", challenge.ID)
				fmt.Printf("  - User ID: %s\n", challenge.UserID)
				fmt.Printf("  - Type: %s\n", challenge.Type)
				fmt.Printf("  - Expires: %s\n", challenge.ExpiresAt.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Printf("  - Raw data: %s\n", string(value))
			}
		} else {
			otherCount++
			fmt.Printf("Type: Other\n")
			if len(value) > 200 {
				fmt.Printf("  - Raw data (truncated): %s...\n", string(value[:200]))
			} else {
				fmt.Printf("  - Raw data: %s\n", string(value))
			}
		}
	}

	if err := iter.Error(); err != nil {
		log.Fatalf("Iterator error: %v", err)
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Credentials: %d\n", credentialCount)
	fmt.Printf("Challenges: %d\n", challengeCount)
	fmt.Printf("Other keys: %d\n", otherCount)
}
