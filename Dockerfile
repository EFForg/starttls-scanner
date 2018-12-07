FROM golang:1.10

WORKDIR /go/src/github.com/EFForg/starttls-backend

RUN apt-get update && apt-get -y install postgresql

ADD . .

RUN go get github.com/EFForg/starttls-backend

ENTRYPOINT ["/go/src/github.com/EFForg/starttls-backend/entrypoint.sh"]

EXPOSE 8080
