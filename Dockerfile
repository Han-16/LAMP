FROM golang:1.25.6-bookworm

WORKDIR /workspace

ENV GOWORK=off

COPY . .

RUN go mod download

RUN go build -o /usr/local/bin/lamp ./cmd/lamp
RUN go build -o /usr/local/bin/lamp_batch ./cmd/lamp_batch
RUN go build -o /usr/local/bin/lamp_gpt2 ./cmd/lamp_gpt2
RUN go build -o /usr/local/bin/freivalds ./cmd/freivalds
RUN go build -o /usr/local/bin/freivalds_batch ./cmd/freivalds_batch
RUN go build -o /usr/local/bin/freivalds_gpt2 ./cmd/freivalds_gpt2
