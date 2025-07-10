FROM golang:1.24.3-alpine


WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN go build -o main .

CMD ["./main"]
