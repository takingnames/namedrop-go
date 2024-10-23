module github.com/takingnames/namedrop-go

go 1.22.4

toolchain go1.22.6

replace github.com/anderspitman/little-oauth2-go => ../little-oauth2-go

replace github.com/libdns/namedotcom => ../namedotcom

require (
	github.com/anderspitman/little-oauth2-go v0.0.0-20240904162115-5d18e06f4a81
	github.com/caddyserver/certmagic v0.15.2
	github.com/lastlogin-io/obligator v0.0.0-20241004152347-442aa1afb59a
	github.com/libdns/libdns v0.2.2
	github.com/libdns/namedotcom v0.3.3
	github.com/mdp/qrterminal/v3 v3.2.0
	github.com/takingnames/namedrop-libdns v0.0.0-20240917203258-1f9519ecccd9
	golang.org/x/oauth2 v0.23.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/ip2location/ip2location-go/v9 v9.6.0 // indirect
	github.com/jmoiron/sqlx v1.3.5 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/lestrrat-go/blackmagic v1.0.1 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.4 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.0.11 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.18 // indirect
	github.com/mholt/acmez v1.0.1 // indirect
	github.com/miekg/dns v1.1.43 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.14.0 // indirect
	golang.org/x/term v0.13.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	lukechampine.com/uint128 v1.2.0 // indirect
	rsc.io/qr v0.2.0 // indirect
)
