# Start from a Debian image with the latest version of Go installed
# and a workspace (GOPATH) configured at /go.
FROM golang

# Copy the local package files to the container's workspace.
ADD . /go/src/github.com/bvandewa/libnetwork-plugin

# This is still a private package
ADD vendor/ /go/src/github.com/nuagenetworks/libvrsovsdb

WORKDIR /go/src/github.com/bvandewa/libnetwork-plugin
RUN go get -v
RUN go install github.com/bvandewa/libnetwork-plugin

ENTRYPOINT /go/bin/libnetwork-plugin
