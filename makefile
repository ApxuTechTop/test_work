build:
	docker build -t test_auth .
run:
	docker run -p3678:80 -d test_auth