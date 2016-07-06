package nuage

import (
	"fmt"
	"net"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/types"
)

type nuageInfo struct {
	NuageSubnetID string
	User          string
	Enterprise    string
	Domain        string
	Zone          string
}

type network struct {
	id        string
	endpoints endpointTable
	gateway   string
	nuage     *nuageInfo
	sync.Mutex
	cidr *net.IPNet
}

type networkTable map[string]*network

type endpoint struct {
	id        string
	sandboxID string
	mac       net.HardwareAddr
	addr      net.IP
	mask      *net.IPNet
	srcName   string
}

type endpointTable map[string]*endpoint

func (d *Driver) getNetwork(id string) (*network, error) {
	d.Lock()
	defer d.Unlock()
	if id == "" {
		return nil, types.BadRequestErrorf("invalid network id: %s", id)
	}
	if nw, ok := d.networks[id]; ok {
		return nw, nil
	}
	return nil, types.NotFoundErrorf("network not found: %s", id)
}

func (n *network) endpoint(eid string) *endpoint {
	n.Lock()
	defer n.Unlock()
	return n.endpoints[eid]
}

func (n *network) addEndpoint(ep *endpoint) {
	n.Lock()
	n.endpoints[ep.id] = ep
	n.Unlock()
}

func (n *network) deleteEndpoint(eid string) {
	n.Lock()
	delete(n.endpoints, eid)
	n.Unlock()
}

func (n *network) getEndpoint(eid string) (*endpoint, error) {
	n.Lock()
	defer n.Unlock()
	if eid == "" {
		return nil, fmt.Errorf("endpoint id %s not found", eid)
	}
	if ep, ok := n.endpoints[eid]; ok {
		return ep, nil
	}
	return nil, nil
}

func (d *Driver) network(nid string) *network {
	d.Lock()
	networks := d.networks
	d.Unlock()
	n, ok := networks[nid]
	if !ok {
		logrus.Errorf("network id %s not found", nid)
	}
	return n
}

func (d *Driver) addNetwork(n *network) {
	d.Lock()
	d.networks[n.id] = n
	d.Unlock()
}

func (d *Driver) deleteNetwork(nid string) {
	d.Lock()
	delete(d.networks, nid)
	d.Unlock()
}

// Safely return a slice of existng networks
func (d *Driver) getNetworks() []*network {
	d.Lock()
	defer d.Unlock()
	ls := make([]*network, 0, len(d.networks))
	for _, nw := range d.networks {
		ls = append(ls, nw)
	}
	return ls
}
