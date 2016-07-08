package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/bvandewa/libn1/nuage"
	"github.com/docker/go-plugins-helpers/network"
)

const (
	version = "0.1"
)

func main() {
	log.SetLevel(log.DebugLevel)
	log.Println("Starting Nuage LibNetwork Experimental Plugin")
	d, err := nuage.NewDriver(version)
	if err != nil {
		panic(err)
	}
	h := network.NewHandler(d)
	h.ServeUnix("root", "nuage")
}
