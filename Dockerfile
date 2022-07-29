FROM golang:1.18 as builder
WORKDIR /go/src
COPY . .
RUN make build

FROM alpine
COPY --from=builder /go/src/bin/test-xss /usr/bin
ENTRYPOINT [ "test-xss" ]