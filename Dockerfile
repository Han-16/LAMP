FROM golang:1.25.6-bookworm

WORKDIR /workspace

ENV GOWORK=off

COPY . .

RUN go mod download
