export GOTOOLCHAIN := "go1.26.0"

default: verify

verify: fmt vet lint test build

fmt:
    test -z "$(gofmt -l cmd internal)"

vet:
    go vet ./...

lint:
    golangci-lint run ./...

test:
    go test ./...

race:
    go test -race ./...

build:
    go build -o bin/kubeflock ./cmd/kubeflock

helm:
    helm lint charts/kubeflock --values charts/kubeflock/values.example.yaml
    helm template kubeflock charts/kubeflock --namespace developer --values charts/kubeflock/values.example.yaml --set sandbox.sshPort=2200 > /dev/null

image:
    docker build --tag kubeflock-sandbox:test sandbox-image
    sandbox-image/test.sh kubeflock-sandbox:test
