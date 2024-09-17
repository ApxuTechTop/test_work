FROM golang AS builder
WORKDIR /code
COPY . /code
ENV GOPROXY=direct
RUN go mod tidy
RUN go build -o main main.go
FROM dokken/ubuntu-22.04
WORKDIR /app
COPY --from=builder /code/main /app/main
EXPOSE 80
RUN chmod +x main
CMD /app/main