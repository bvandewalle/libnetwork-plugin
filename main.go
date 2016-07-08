package main

import (
	"fmt"

	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	"github.com/bvandewa/libn1/nuage"
	"github.com/docker/go-plugins-helpers/network"
)

const (
	version = "0.1"
)

func main() {
	log.Warnf("Starting Nuage LibNetwork Experimental Plugin version %s", version)
	log.Warnf("LocalSope version Driver ")

	//setdefault
	conf := nuage.Config{
		VrsEndpoint:    "localhost",
		VrsPort:        6633,
		VrsBridge:      "alubr0",
		DockerEndpoint: "unix:///var/run/docker.sock",
		LogLevel:       "Info",
	}
	if _, err := toml.DecodeFile("nuage.cfg", &conf); err != nil {
		fmt.Println("Couldnt load config")
	}

	if conf.LogLevel == "Debug" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	d, err := nuage.NewDriver(version, conf)
	if err != nil {
		panic(err)
	}

	h := network.NewHandler(d)
	h.ServeUnix("root", "nuage")
}
