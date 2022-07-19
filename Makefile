.EXPORT_ALL_VARIABLES:
VERSION := $(shell git describe --tags)
COMMIT := $(shell git rev-parse --short HEAD)
# PROJECTNAME := $(shell basename "$(PWD)")
PROJECTNAME := nacli

LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Commit=$(COMMIT)"
STDERR := /tmp/.$(PROJECTNAME)-stderr.txt

.PHONY: run
run:
	go run main.go 

.PHONY: build
build:
	go build $(LDFLAGS) -o dist/$(PROJECTNAME)
	chmod +x dist/$(PROJECTNAME)

.PHONY: docker
docker:
	docker build -t nuxion/${PROJECTNAME} .

.PHONY: release
release: docker
	docker tag nuxion/${PROJECTNAME} nuxion/${PROJECTNAME}:$(VERSION)
	docker push nuxion/$(PROJECTNAME):$(VERSION)
