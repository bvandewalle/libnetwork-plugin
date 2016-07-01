# Start from a Debian image with the latest version of Go installed
# and a workspace (GOPATH) configured at /go.
FROM golang

# Copy the local package files to the container's workspace.
ADD . /go/src/github.com/bvandewa/libn1

# Build the outyet command inside the container.
# (You may fetch or manage dependencies here,
# either manually or with a tool like "godep".)
RUN go get "github.com/docker/go-plugins-helpers/network"
RUN go install github.com/bvandewa/libn1

ENTRYPOINT /go/bin/libn1
