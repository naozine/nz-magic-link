package main

import (
	"log"
	"os"

	"github.com/resend/resend-go/v3"
)

func main() {
	apiKey := os.Getenv("RESEND_API_KEY")

	client := resend.NewClient(apiKey)

	params := &resend.SendEmailRequest{
		From:    "you@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "Hello World",
		Html:    "<p>Congrats on sending your <strong>first email</strong>!</p>",
	}

	sent, err := client.Emails.Send(params)
	if err != nil {
		log.Fatalf("failed to send email: %v", err)
	}

	log.Printf("email sent: %s", sent.Id)
}
