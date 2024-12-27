
all: build push

build:
	docker build -t fossorial/newt:latest .

push:
	docker push fossorial/newt:latest

test:
	docker run fossorial/newt:latest

local: 
	 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o newt

clean:
	rm newt