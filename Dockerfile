FROM golang:1.22-alpine

ARG TZ=Asia/Taipei

ENV TZ=${TZ}

RUN apk add --no-cache tzdata

# create a working directory inside the image
WORKDIR /app

# copy Go modules and dependencies to image
COPY go.mod go.sum ./

# download Go modules and dependencies
RUN go mod download

# copy directory files i.e all files ending with .go
COPY  . .

# compile application
RUN go build

# tells Docker that the container listens on specified network ports at runtime
EXPOSE 8082

ENTRYPOINT [ "/app/grafana-auth-reverse-proxy" ]
