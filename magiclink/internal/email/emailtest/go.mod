module github.com/naozine/nz-magic-link/magiclink/internal/email/emailtest

go 1.24.0

require (
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
	github.com/emersion/go-smtp v0.24.0
	github.com/naozine/nz-magic-link v0.0.0
)

replace github.com/naozine/nz-magic-link => ../../../..
