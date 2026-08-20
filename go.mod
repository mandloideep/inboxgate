module github.com/mandloideep/inboxgate

go 1.26.0

toolchain go1.26.6

require (
	github.com/modelcontextprotocol/go-sdk v1.7.0
	go.yaml.in/yaml/v3 v3.0.5
	turso.tech/database/tursogo-serverless v0.0.0-20260817122138-24adc316cdc4
)

replace turso.tech/database/tursogo-serverless => ./third_party/tursogo-serverless

require golang.org/x/oauth2 v0.36.0

require (
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
