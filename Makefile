GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
VERSION=$(shell git describe --tags)
DEBUG_LDFLAGS=''
RELEASE_LDFLAGS='-s -w -X main.version=$(VERSION)'
BUILD_TAGS?=socks
BUILDDIR=$(shell pwd)/build
CMDDIR=$(shell pwd)/cmd/tun2socks
PROGRAM=tun2socks
GOOS:=$(strip $(shell go env GOOS))
GOARCHs:=$(strip $(shell go env GOARCH))

ifeq "$(GOOS)" "windows"
SUFFIX=.exe
endif

.PHONY: build

all: fmt build

build:
	$(foreach GOARCH,$(GOARCHs),$(shell GOARCH=$(GOARCH) $(GOBUILD) -ldflags $(RELEASE_LDFLAGS) -trimpath -o $(BUILDDIR)/$(PROGRAM)_$(GOOS)_$(GOARCH)$(SUFFIX) -v -tags '$(BUILD_TAGS)' $(CMDDIR)))

fmt:
	gofmt -w -s .

clean:
	rm -rf $(BUILDDIR)

cleancache:
	# go build cache may need to cleanup if changing C source code
	$(GOCLEAN) -cache
	rm -rf $(BUILDDIR)
