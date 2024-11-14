module github.com/takingnames/namedrop-go

go 1.23.1

replace github.com/anderspitman/little-oauth2-go => ../little-oauth2-go

replace github.com/libdns/namedotcom => ../namedotcom

replace github.com/lastlogin-net/decent-auth-go => ../decent-auth-go

replace github.com/philippgille/gokv => ../gokv

//replace github.com/philippgille/gokv/sqlite => ../gokv/sqlite

require (
	github.com/anderspitman/little-oauth2-go v0.0.0-20240920175702-3cf95e45e957
	github.com/caddyserver/certmagic v0.15.2
	github.com/lastlogin-net/decent-auth-go v0.0.0-20241114224805-c499a68f6a21
	github.com/libdns/libdns v0.2.2
	github.com/libdns/namedotcom v0.3.3
	github.com/mattn/go-sqlite3 v1.14.18
	github.com/mdp/qrterminal/v3 v3.2.0
	github.com/philippgille/gokv v0.7.0
	github.com/takingnames/gokv/sqlite v0.0.0-20241110231501-cc717df19c7d
	golang.org/x/oauth2 v0.23.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mholt/acmez v1.0.1 // indirect
	github.com/miekg/dns v1.1.43 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/philippgille/gokv/encoding v0.7.0 // indirect
	github.com/philippgille/gokv/gomap v0.7.0 // indirect
	github.com/philippgille/gokv/sql v0.7.0 // indirect
	github.com/philippgille/gokv/util v0.7.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/term v0.13.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/sqlite v1.33.1 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
	rsc.io/qr v0.2.0 // indirect
)
