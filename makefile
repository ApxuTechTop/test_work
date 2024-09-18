.PHONY: build run test

build:
	docker compose build
run:
	docker compose up
test:
	go test -run ^TestAll$ test_auth/testing