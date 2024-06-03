.DEFAULT_GOAL := build

.PHONY:fmt vet build

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

build: vet
	go build -o build/phobos

clean:
	go clean

test:
	go test -v ./...

lint:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

vulncheck:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...