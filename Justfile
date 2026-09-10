export GOTOOLCHAIN := "go1.27.1"

default: verify

verify: fmt vet lint test build

vuln:
    govulncheck ./...

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
    helm template kubeflock charts/kubeflock --namespace developer --values charts/kubeflock/values.example.yaml --set sandbox.sshPort=2200 | grep -q 'replicas: 0'
    helm template kubeflock charts/kubeflock --namespace developer --values charts/kubeflock/values.example.yaml --set capacity.warmStandbys=1 | grep -q 'type: Recreate'
    helm template kubeflock charts/kubeflock --namespace developer --values charts/kubeflock/values.example.yaml | grep -q 'volumeClaimTemplatesPolicy: Overrides'
    ! helm template kubeflock charts/kubeflock --namespace developer --values charts/kubeflock/values.example.yaml --set capacity.warmStandbys=3 > /dev/null 2>&1

image:
    docker build --tag kubeflock-sandbox:test sandbox-image
