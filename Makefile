
all: build push

build:
	docker build -t fosrl/newt:latest .

push:
	docker push fosrl/newt:latest

test:
	docker run fosrl/newt:latest

local: 
	 CGO_ENABLED=0 go build -o newt

clean:
	rm newt
