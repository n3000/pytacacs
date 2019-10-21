build:
	docker build -t tacacs .

push: build
	docker tag tacacs:latest terrycain/pytacacs:latest
	docker push terrycain/pytacacs:latest
