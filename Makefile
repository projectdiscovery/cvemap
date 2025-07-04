# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v
# This should be disabled if the binary uses pprof
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "cvemap" cmd/cvemap/main.go
build-vulnsh:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS) -X github.com/projectdiscovery/cvemap/cmd/vulnsh/clis.Version=v1.0.0' -o "vulnsh" cmd/vulnsh/main.go
integration:
	cd cmd/integration-test; bash run.sh
tidy:
	$(GOMOD) tidy
