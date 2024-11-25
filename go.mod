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
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/mdp/qrterminal/v3 v3.2.0
	golang.org/x/oauth2 v0.23.0
)

require (
	github.com/dylibso/observe-sdk/go v0.0.0-20240819160327-2d926c5d788a // indirect
	github.com/extism/go-sdk v1.6.1 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20240805132620-81f5be970eca // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/mholt/acmez v1.0.1 // indirect
	github.com/miekg/dns v1.1.43 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tetratelabs/wabin v0.0.0-20230304001439-f6f874872834 // indirect
	github.com/tetratelabs/wazero v1.8.1-0.20240916092830-1353ca24fef0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/term v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	rsc.io/qr v0.2.0 // indirect
)
