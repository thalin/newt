
all: build push

build:
	docker build -t fosrl/newt:latest .

push:
	docker push fosrl/newt:latest

test:
	docker run fosrl/newt:latest

local: 
	CGO_ENABLED=0 go build -o newt

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/newt_linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/newt_linux_amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/newt_darwin_arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/newt_darwin_amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/newt_windows_amd64.exe
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o bin/newt_freebsd_amd64
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -o bin/newt_freebsd_arm64

clean:
	rm newt
