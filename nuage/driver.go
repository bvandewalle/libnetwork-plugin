package nuage

import (
	"fmt"
	"net"
	"sync"

	log "github.com/Sirupsen/logrus"
	dockerSdk "github.com/docker/go-plugins-helpers/network"
	vrsSdk "github.com/nuagenetworks/libvrsovsdb/api"
	"github.com/nuagenetworks/libvrsovsdb/api/entity"
	"github.com/nuagenetworks/libvrsovsdb/api/port"
	"github.com/samalba/dockerclient"
)

const (
	bridgeMode           = "bridge"
	bridgeName           = "alubr0"
	containerIfacePrefix = "eth"
	basePrefix           = "veth"
	internalPrefix       = "neth"
	defaultMTU           = 1500
	minMTU               = 68
)

// Driver is the Nuage Driver
type driver struct {
	dockerSdk.Driver
	dclient       dockerclient.DockerClient
	vrsConnection vrsSdk.VRSConnection
	sync.Mutex
	networks networkTable
}

// NewDriver creates a new Nuage Driver
func NewDriver(version string) (dockerSdk.Driver, error) {
	log.Println("NewDriver called")

	docker, err := dockerclient.NewDockerClient("unix:///var/run/docker.sock", nil)
	if err != nil {
		return nil, fmt.Errorf("could not connect to docker: %s", err)
	}

	vrsConnection, err := vrsSdk.NewConnection("10.31.1.195", 6633)

	if err != nil {
		return nil, fmt.Errorf("Couldn't connect to VRS: %s", err)
	}

	d := &driver{
		networks:      networkTable{},
		dclient:       *docker,
		vrsConnection: vrsConnection,
	}
	return d, nil
}

// GetCapabilities tells libnetwork this driver is local scope
func (d *driver) GetCapabilities() (*dockerSdk.CapabilitiesResponse, error) {
	scope := &dockerSdk.CapabilitiesResponse{Scope: dockerSdk.LocalScope}
	log.Debugf("GetCapabilities")
	return scope, nil
}

//Simple func to print all the networks and related Nuage information
func printNetworks(net networkTable) {
	log.Debugf("%d Existing networks", len(net))

	for _, v := range net {
		log.Debugf("Network %s CIDR: %s Nuage Info: Enterprise: %s - User: %s - Domain: %s - Zone: %s - Subnet: %s ", v.id, v.cidr.IP, v.nuage.Enterprise, v.nuage.User, v.nuage.Domain, v.nuage.Zone, v.nuage.NuageSubnetID)
	}
}

// CreateNetwork creates a new Network and links it to an Existing network based on the Options given
func (d *driver) CreateNetwork(r *dockerSdk.CreateNetworkRequest) (err error) {

	var netCidr *net.IPNet
	var netGw string

	log.Debugf("Network Create Called: [ %+v ]", r)

	for _, v4 := range r.IPv4Data {
		netGw = v4.Gateway
		_, netCidr, err = net.ParseCIDR(v4.Pool)

		if err != nil {
			return err
		}
	}

	nuage := &nuageInfo{}

	net := &network{
		id:        r.NetworkID,
		endpoints: endpointTable{},
		cidr:      netCidr,
		gateway:   netGw,
		nuage:     nuage,
	}

	//Getting all the options from the User
	for k, v := range r.Options {
		log.Println(k, v)

		if k != "com.docker.network.generic" {
			continue
		}

		genericOpts, ok := v.(map[string]interface{})

		if !ok {
			continue
		}

		for key, val := range genericOpts {
			log.Debugf("Libnetwork Opts Sent: [ %s ] Value: [ %s ]", key, val)
			// Parse -o host_iface from libnetwork generic opts
			switch key {
			case "enterprise":
				nuage.Enterprise = val.(string)
			case "domain":
				nuage.Domain = val.(string)
			case "zone":
				nuage.Zone = val.(string)
			case "subnet":
				nuage.NuageSubnetID = val.(string)
			case "user":
				nuage.User = val.(string)
			}

		}
	}

	log.Infof("Creating Network %s CIDR: %s Nuage Info: Enterprise: %s - User: %s - Domain: %s - Zone: %s - Subnet: %s ", net.id, net.cidr.IP, nuage.Enterprise, nuage.User, nuage.Domain, nuage.Zone, nuage.NuageSubnetID)
	d.addNetwork(net)
	printNetworks(d.networks)
	return nil
}

// DeleteNetwork deletes a network kn Libnetwork. The corresponding network in Nuage VSD is NOT deleted.
func (d *driver) DeleteNetwork(r *dockerSdk.DeleteNetworkRequest) error {
	log.Debugf("DeleteNetwork Called")
	log.Infof("Deleting Network %s ", r.NetworkID)
	d.deleteNetwork(r.NetworkID)
	return nil
}

// CreateEndpoint creates a new MACVLAN Endpoint
func (d *driver) CreateEndpoint(r *dockerSdk.CreateEndpointRequest) (*dockerSdk.CreateEndpointResponse, error) {
	log.Debugf("CreateEndpoint Called")
	var mac net.HardwareAddr
	var ip net.IP
	var mask *net.IPNet

	endID := r.EndpointID
	log.Debugf("The container IP and MAC requested for this endpoint is [ %s , %s]", r.Interface.Address, r.Interface.MacAddress)

	if r.Interface.Address == "" {
		return nil, fmt.Errorf("Unable to obtain an IP address from libnetwork default ipam")
	}

	// Parsing IP as Standard Net objects.
	ip, mask, err := net.ParseCIDR(r.Interface.Address)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse address %v", err)
	}

	// generate a mac address for the pending container
	// Honor MAC if explicitely requested, Generate one if not
	if r.Interface.MacAddress == "" {
		mac, err = makeMac()
		if err != nil {
			return nil, fmt.Errorf("Couldnt generate MAC %v", err)
		}
	} else {
		mac, err = net.ParseMAC(r.Interface.MacAddress)
		if err != nil {
			return nil, fmt.Errorf("Couldnt parse MAC %v", err)
		}
	}

	// Respond with the MAC/IP Address
	res := &dockerSdk.CreateEndpointResponse{
		Interface: &dockerSdk.EndpointInterface{
			//Address:    containerAddress,
			MacAddress: mac.String(),
		},
	}

	// Keep the state locally for this endpoint
	ep := &endpoint{
		id:   endID,
		addr: ip,
		mac:  mac,
		mask: mask,
	}

	networkInfo, err := d.getNetwork(r.NetworkID)

	if err != nil {
		// Init any existing libnetwork networks
		d.existingNetChecks()

		networkInfo, err = d.getNetwork(r.NetworkID)
		if err != nil {
			return nil, fmt.Errorf("error getting network ID [ %s ]. Run 'docker network ls' or 'docker network create' Err: %v", r.NetworkID, err)
		}
	}

	networkInfo.addEndpoint(ep)

	log.Infof("Endpoint [ %s ] .Allocated container IP: [ %s ]. Allocated/Generated container MAC: [ %s ][ %s ]", r.EndpointID, ip.String(), r.Interface.MacAddress, mac.String())
	log.Debugf("Create endpoint response: %+v", res)

	return res, nil
}

// DeleteEndpoint deletes a Nuage Endpoint
func (d *driver) DeleteEndpoint(r *dockerSdk.DeleteEndpointRequest) error {
	log.Debugf("Delete endpoint request: %+v", &r)
	//TODO: null check cidr in case driver restarted and doesn't know the network to avoid panic
	return nil
}

// EndpointInfo returns informatoin about a Nuage endpoint
func (d *driver) EndpointInfo(r *dockerSdk.InfoRequest) (*dockerSdk.InfoResponse, error) {
	log.Debugf("Endpoint info request: %+v", &r)
	res := &dockerSdk.InfoResponse{
		Value: make(map[string]string),
	}
	return res, nil
}

// Join creates a Nuage interface to be moved to the container netns
func (d *driver) Join(r *dockerSdk.JoinRequest) (*dockerSdk.JoinResponse, error) {
	log.Debugf("Join request: %+v", &r)

	//Getting the network information from local store
	networkInfo, err := d.getNetwork(r.NetworkID)
	if err != nil {
		// Init any existing libnetwork networks
		d.existingNetChecks()

		networkInfo, err = d.getNetwork(r.NetworkID)
		if err != nil {
			return nil, fmt.Errorf("error getting network ID [ %s ]. Run 'docker network ls' or 'docker network create' Err: %v", r.NetworkID, err)
		}
	}

	//Getting the Mac/IP info from local store
	endpointInfo, err := networkInfo.getEndpoint(r.EndpointID)
	if err != nil {
		return nil, fmt.Errorf("error getting network ID [ %s ]. Run 'docker network ls' or 'docker network create' Err: %v", r.NetworkID, err)
	}

	log.Debugf("Join Request for Endpoint: %v to Network: %v ", endpointInfo, networkInfo)

	//Finding the Name and UUID of the container by calling directly Docker API
	netInspect, err := d.dclient.InspectNetwork(r.NetworkID)
	var containerName, containerUUID string
	for _, containerInspect := range netInspect.Containers {
		if containerInspect.EndpointID == r.EndpointID {
			containerName = containerInspect.Name
			containerUUID = containerInspect.EndpointID
			break
		}
	}
	if containerName == "" {
		return nil, fmt.Errorf("Couldn't find Container")
	}

	endpointInfo.sandboxID = containerUUID

	// ContainerInfo contains all the relevant parameter of the container instance that needs to be activated
	containerInfo := make(map[string]string)
	containerInfo["name"] = containerName
	containerInfo["mac"] = endpointInfo.mac.String()
	containerInfo["vmuuid"] = containerUUID
	containerInfo["entityport"] = internalPrefix + truncateID(r.EndpointID)
	containerInfo["brport"] = basePrefix + truncateID(r.EndpointID)
	portList := []string{containerInfo["entityport"], containerInfo["brport"]}
	err = createVETHPair(portList)

	if err != nil {
		return nil, fmt.Errorf("Unable to create veth pairs on VRS")
	}

	log.Debugf("ContainerInfo: %v", containerInfo)

	// Add the paired veth port to alubr0 on VRS
	err = addVETHPortToVRS(containerInfo["brport"], containerInfo["vmuuid"], containerInfo["name"])
	if err != nil {
		return nil, fmt.Errorf("Unable to add veth port to alubr0")
	}

	// Create Port Attributes
	portAttributes := port.Attributes{
		Platform: entity.TypeDocker,
		MAC:      containerInfo["mac"],
		Bridge:   "alubr0",
	}

	// Create Port Metadata
	portMetadata := make(map[port.MetadataKey]string)
	portMetadata[port.MetadataKeyDomain] = networkInfo.nuage.Domain
	portMetadata[port.MetadataKeyNetwork] = networkInfo.nuage.NuageSubnetID
	portMetadata[port.MetadataKeyZone] = networkInfo.nuage.Zone
	portMetadata[port.MetadataKeyNetworkType] = "ipv4"
	ip := endpointInfo.addr.String()
	fmt.Println(ip)
	portMetadata[port.MetadataKeyStaticIP] = ip

	// Associate one veth port to entity
	err = d.vrsConnection.CreatePort(containerInfo["brport"], portAttributes, portMetadata)
	if err != nil {
		return nil, fmt.Errorf("Unable to create entity port %v", err)
	}

	// Create VM metadata
	vmMetadata := make(map[entity.MetadataKey]string)
	vmMetadata[entity.MetadataKeyUser] = networkInfo.nuage.User
	vmMetadata[entity.MetadataKeyEnterprise] = networkInfo.nuage.Enterprise

	// Define ports associated with the VM
	ports := []string{containerInfo["brport"]}

	// Add entity to the VRS
	entityInfo := vrsSdk.EntityInfo{
		UUID:     containerInfo["vmuuid"],
		Name:     containerInfo["name"],
		Type:     entity.TypeDocker,
		Ports:    ports,
		Metadata: vmMetadata,
	}

	err = d.vrsConnection.AddEntity(entityInfo)
	if err != nil {
		return nil, fmt.Errorf("Unable to add entity to VRS %v", err)
	}

	// Notify VRS that VM has completed booted
	err = d.vrsConnection.PostEntityEvent(containerInfo["vmuuid"], entity.EventCategoryStarted, entity.EventStartedBooted)

	if err != nil {
		return nil, fmt.Errorf("Problem sending VRS notification %v", err)
	}

	// SrcName gets renamed to DstPrefix on the container iface
	ifname := &dockerSdk.InterfaceName{
		SrcName:   containerInfo["entityport"],
		DstPrefix: containerIfacePrefix,
	}

	res := &dockerSdk.JoinResponse{
		InterfaceName: *ifname,
		//Gateway:               getID.gateway,
		DisableGatewayService: true,
	}
	log.Debugf("Join response: %+v", res)
	log.Infof("Join successful for Container %s with IP %s", containerName, ip)
	return res, nil
}

// Leave removes a Nuage Endpoint from a container
func (d *driver) Leave(r *dockerSdk.LeaveRequest) error {
	log.Debugf("Leave request: %+v", &r)

	networkInfo, err := d.getNetwork(r.NetworkID)
	if err != nil {
		return fmt.Errorf("Couldn't find Network to leave %v", err)
	}
	endpointInfo, err := networkInfo.getEndpoint(r.EndpointID)
	if err != nil {
		return fmt.Errorf("Couldn't find endpoint %v", err)
	}

	// ContainerInfo contains all the relevant parameter of the container instance that needs to be activated
	containerInfo := make(map[string]string)
	containerInfo["mac"] = endpointInfo.mac.String()
	containerInfo["vmuuid"] = endpointInfo.sandboxID
	containerInfo["entityport"] = internalPrefix + truncateID(r.EndpointID)
	containerInfo["brport"] = basePrefix + truncateID(r.EndpointID)

	err = d.vrsConnection.RemoveEntity(containerInfo["vmuuid"])
	if err != nil {
		return fmt.Errorf("Unable to remove the entity from OVSDB table %v", err)
	}

	// Performing cleanup of port/entity on VRS
	err = d.vrsConnection.DestroyPort(containerInfo["brport"])
	if err != nil {
		return fmt.Errorf("Unable to delete port from OVSDB table %v", err)
	}

	// Purging out the veth port from VRS alubr0
	err = removeVETHPortFromVRS(containerInfo["brport"])
	if err != nil {
		return fmt.Errorf("Unable to delete veth port as part of cleanup from alubr0 %v", err)
	}

	// Cleaning up veth paired ports from VRS
	err = deleteVETHPair(containerInfo["brport"], containerInfo["entityport"])
	if err != nil {
		return fmt.Errorf("Unable to delete veth pairs as a part of cleanup on VRS %v", err)
	}

	networkInfo.deleteEndpoint(r.EndpointID)
	log.Infof("Leave successful for container %s", r.EndpointID)
	return nil
}

// DiscoverNew is not used by local scoped drivers
func (d *driver) DiscoverNew(r *dockerSdk.DiscoveryNotification) error {
	return nil
}

// DiscoverDelete is not used by local scoped drivers
func (d *driver) DiscoverDelete(r *dockerSdk.DiscoveryNotification) error {
	return nil
}

// existingNetChecks checks for networks that already exist in libnetwork cache and add them to this process.
func (d *driver) existingNetChecks() error {
	// Request all networks on the endpoint without any filters
	existingNets, err := d.dclient.ListNetworks("")
	if err != nil {
		return fmt.Errorf("unable to retrieve existing networks: %v", err)
	}
	var netCidr *net.IPNet
	var netGW string
	for _, n := range existingNets {
		// Only add the nuage nets.
		if n.Driver == "nuage" {
			for _, v4 := range n.IPAM.Config {
				netGW = v4.Gateway
				netCidr, err = parseIPNet(v4.Subnet)
				if err != nil {
					return fmt.Errorf("invalid cidr address in network [ %s ]: %v", v4.Subnet, err)
				}
			}

			nuage := &nuageInfo{}

			nw := &network{
				id:        n.ID,
				endpoints: endpointTable{},
				cidr:      netCidr,
				gateway:   netGW,
				nuage:     nuage,
			}

			// Parse docker network -o opts
			for key, val := range n.Options {
				// log.Debugf("Libnetwork Opts Sent: [ %s ] Value: [ %s ]", key, val)
				// Parse -o host_iface from libnetwork generic opts
				switch key {
				case "enterprise":
					nuage.Enterprise = val
				case "domain":
					nuage.Domain = val
				case "zone":
					nuage.Zone = val
				case "subnet":
					nuage.NuageSubnetID = val
				case "user":
					nuage.User = val
				}
				d.addNetwork(nw)
			}
		}
	}
	return nil
}

func truncateID(id string) string {
	return id[:5]
}
