GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
VERSION=$(shell git describe --tags)
DEBUG_LDFLAGS=''
RELEASE_LDFLAGS='-s -w -X main.version=$(VERSION)'
STATIC_RELEASE_LDFLAGS='-s -w -X main.version=$(VERSION) -extldflags "-static"'
BUILD_TAGS?=socks
BUILDDIR=$(shell pwd)/build
CMDDIR=$(shell pwd)/cmd/tun2socks
PROGRAM=tun2socks
GOOS:=$(strip $(shell go env GOOS))

ifeq "$(GOOS)" "windows"
SUFFIX=.exe
endif

ifeq "$(GOOS)" "freebsd"
# customized vendor dir with a patch
$(shell go mod vendor)
$(shell patch -si freebsd.patch)
GOBUILD := $(GOBUILD) -mod=vendor
endif

BUILD_CMD="cd $(CMDDIR) && $(GOBUILD) -ldflags $(RELEASE_LDFLAGS) -o $(BUILDDIR)/$(PROGRAM)_$(GOOS)$(SUFFIX) -v -tags '$(BUILD_TAGS)'"

.PHONY: build

all: build

build:
	mkdir -p $(BUILDDIR)
	eval $(BUILD_CMD)

xbuild_linux:
	mkdir -p $(BUILDDIR)
	eval $(XBUILD_LINUX_CMD)

xbuild_others:
	mkdir -p $(BUILDDIR)
	eval $(XBUILD_OTHERS_CMD)

xbuild: xbuild_linux xbuild_others

travisbuild: xbuild

clean:
	rm -rf $(BUILDDIR)

cleancache:
	# go build cache may need to cleanup if changing C source code
	$(GOCLEAN) -cache
	rm -rf $(BUILDDIR)
