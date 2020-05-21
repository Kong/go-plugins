.PHONY: all

all: go-hello.so go-log.so go-jwe.so

go-hello.so: go-hello.go
	go build -buildmode=plugin go-hello.go

go-log.so: go-log.go
	go build -buildmode=plugin go-log.go

go-jwe.so: go-jwe.go
	go build -buildmode=plugin go-jwe.go
