# Description: Makefile for building the project

BINARY_NAME=newt

ll: build

build:
	go build -o bin/$(BINARY_NAME) -v