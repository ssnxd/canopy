module github.com/ssnxd/canopy/adapters/chi

go 1.25.12

toolchain go1.26.5

require (
	github.com/go-chi/chi/v5 v5.2.3
	github.com/ssnxd/canopy v0.1.2
)

require (
	github.com/coreos/go-oidc/v3 v3.20.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/ssnxd/canopy => ../..
