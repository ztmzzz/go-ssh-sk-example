module github.com/ztmzzz/go-ssh-sk-example

go 1.20

require (
	github.com/keys-pub/go-libfido2 v1.5.3
	golang.org/x/crypto v0.20.0
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	golang.org/x/sys v0.17.0 // indirect
)

replace github.com/keys-pub/go-libfido2 v1.5.3 => ./go-libfido2@v1.5.3
