
all: build push

build:
	docker build -t fossorial/newt:latest .

push:
	docker push fossorial/newt:latest

test:
	docker run -it -p 3002:3002 -v ./config_example.json:/config/config.json --cap-add=NET_ADMIN --cap-add=SYS_MODULE newt --config /config/config.json

local: 
	 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o newt

clean:
	rm newt