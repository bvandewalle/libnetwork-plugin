package nuage

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/docker/distribution/uuid"
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
type Driver struct {
	dockerSdk.Driver
	dclient       dockerclient.DockerClient
	vrsConnection vrsSdk.VRSConnection
	sync.Mutex
	networks networkTable
}

// NewDriver creates a new Nuage Driver
func NewDriver(version string) (*Driver, error) {
	log.Println("NewDriver called")

	docker, err := dockerclient.NewDockerClient("unix:///var/run/docker.sock", nil)
	if err != nil {
		return nil, fmt.Errorf("could not connect to docker: %s", err)
	}

	vrsConnection, err := vrsSdk.NewConnection("10.31.1.195", 6633)

	if err != nil {
		fmt.Println("Unable to connect to the VRS")
		return nil, err
	}

	d := &Driver{
		networks:      networkTable{},
		dclient:       *docker,
		vrsConnection: vrsConnection,
	}
	return d, nil
}

// GetCapabilities tells libnetwork this driver is local scope
func (d *Driver) GetCapabilities() (*dockerSdk.CapabilitiesResponse, error) {
	scope := &dockerSdk.CapabilitiesResponse{Scope: dockerSdk.LocalScope}
	log.Println("GetCapabilities")
	return scope, nil
}

//Simple func to print all the networks and related Nuage information
func printNetworks(net networkTable) {
	log.Printf("%d Existing networks", len(net))
	for _, v := range net {
		log.Printf("Network ID: %s", v.id)
		log.Printf("Nuage Info: Enterprise: %s - User: %s - Domain: %s - Zone: %s - Subnet: %s ", v.nuage.Enterprise, v.nuage.User, v.nuage.Domain, v.nuage.Zone, v.nuage.NuageSubnetID)
	}
}

// CreateNetwork creates a new Network and links it to an Existing network based on the Options given
func (d *Driver) CreateNetwork(r *dockerSdk.CreateNetworkRequest) error {

	var netCidr *net.IPNet
	var netGw string
	var err error
	log.Printf("Network Create Called: [ %+v ]", r)
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
		if k == "com.docker.network.generic" {
			if genericOpts, ok := v.(map[string]interface{}); ok {
				for key, val := range genericOpts {
					log.Printf("Libnetwork Opts Sent: [ %s ] Value: [ %s ]", key, val)
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
		}
	}

	d.addNetwork(net)
	printNetworks(d.networks)
	return nil
}

// DeleteNetwork deletes a network kn Libnetwork. The corresponding network in Nuage VSD is NOT deleted.
func (d *Driver) DeleteNetwork(r *dockerSdk.DeleteNetworkRequest) error {
	log.Println("DeleteNetwork")
	d.deleteNetwork(r.NetworkID)
	return nil
}

// CreateEndpoint creates a new MACVLAN Endpoint
func (d *Driver) CreateEndpoint(r *dockerSdk.CreateEndpointRequest) (*dockerSdk.CreateEndpointResponse, error) {

	var mac net.HardwareAddr
	var ip net.IP
	var mask *net.IPNet

	endID := r.EndpointID
	log.Printf("The container IP and MAC requested for this endpoint is [ %s , %s]", r.Interface.Address, r.Interface.MacAddress)

	if r.Interface.Address == "" {
		return nil, fmt.Errorf("Unable to obtain an IP address from libnetwork default ipam")
	}

	// Parsing IP as Standard Net objects.
	ip, mask, err := net.ParseCIDR(r.Interface.Address)
	if err != nil {
		log.Println("Failed to parse address")
	}

	// generate a mac address for the pending container
	// Honor MAC if explicitely requested, Generate one if not
	if r.Interface.MacAddress == "" {
		mac, err = makeMac()
		if err != nil {
			log.Println("Couldnt generate MAC")
			return nil, nil
		}
	} else {
		mac, err = net.ParseMAC(r.Interface.MacAddress)
		if err != nil {
			log.Println("Couldnt parse MAC")
			return nil, nil
		}
	}

	log.Printf("Allocated container IP: [ %s ]", ip.String())
	log.Printf("Allocated/Generated container MAC: [ %s ][ %s ]", r.Interface.MacAddress, mac.String())

	// Respond with the MAC/IP Address
	res := &dockerSdk.CreateEndpointResponse{
		Interface: &dockerSdk.EndpointInterface{
			//Address:    containerAddress,
			MacAddress: mac.String(),
		},
	}

	log.Printf("Create endpoint response: %+v", res)

	// Keep the state locally for this endpoint
	ep := &endpoint{
		id:   endID,
		addr: ip,
		mac:  mac,
		mask: mask,
	}
	d.network(r.NetworkID).addEndpoint(ep)

	return res, nil
}

// DeleteEndpoint deletes a Nuage Endpoint
func (d *Driver) DeleteEndpoint(r *dockerSdk.DeleteEndpointRequest) error {
	log.Printf("Delete endpoint request: %+v", &r)
	//TODO: null check cidr in case driver restarted and doesn't know the network to avoid panic
	log.Printf("Delete endpoint %s", r.EndpointID)
	return nil
}

// EndpointInfo returns informatoin about a Nuage endpoint
func (d *Driver) EndpointInfo(r *dockerSdk.InfoRequest) (*dockerSdk.InfoResponse, error) {
	log.Printf("Endpoint info request: %+v", &r)
	res := &dockerSdk.InfoResponse{
		Value: make(map[string]string),
	}
	return res, nil
}

// Join creates a Nuage interface to be moved to the container netns
func (d *Driver) Join(r *dockerSdk.JoinRequest) (*dockerSdk.JoinResponse, error) {
	log.Printf("Join request: %+v", &r)

	networkInfo, err := d.getNetwork(r.NetworkID)
	endpointInfo, err := networkInfo.getEndpoint(r.EndpointID)
	endpointInfo.sandboxID = uuid.Generate().String()

	log.Printf("Join Request for Endpoint: %v to Network: %v ", endpointInfo, networkInfo)

	// ContainerInfo contains all the relevant parameter of the container instance that needs to be activated
	containerInfo := make(map[string]string)
	containerInfo["name"] = fmt.Sprintf("Test-VM-%d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(100))
	containerInfo["mac"] = endpointInfo.mac.String()
	containerInfo["vmuuid"] = endpointInfo.sandboxID
	containerInfo["entityport"] = internalPrefix + truncateID(r.EndpointID)
	containerInfo["brport"] = basePrefix + truncateID(r.EndpointID)
	portList := []string{containerInfo["entityport"], containerInfo["brport"]}
	err = createVETHPair(portList)
	if err != nil {
		fmt.Println("Unable to create veth pairs on VRS")
	}
	log.Printf("containerInfo: %v", containerInfo)

	// Add the paired veth port to alubr0 on VRS
	err = addVETHPortToVRS(containerInfo["brport"], containerInfo["vmuuid"], containerInfo["name"])
	if err != nil {
		fmt.Println("Unable to add veth port to alubr0")
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
		fmt.Printf("Unable to create entity port %v", err)
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
		fmt.Printf("Unable to add entity to VRS %v", err)
	}

	// Notify VRS that VM has completed booted
	err = d.vrsConnection.PostEntityEvent(containerInfo["vmuuid"], entity.EventCategoryStarted, entity.EventStartedBooted)

	if err != nil {
		fmt.Printf("Problem sending VRS notification %v", err)
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
	log.Printf("Join response: %+v", res)
	log.Printf("Join endpoint %s:%s to %s", r.NetworkID, r.EndpointID, r.SandboxKey)
	return res, nil
}

// Leave removes a Nuage Endpoint from a container
func (d *Driver) Leave(r *dockerSdk.LeaveRequest) error {
	log.Printf("Leave request: %+v", &r)
	log.Printf("Leave %s:%s", r.NetworkID, r.EndpointID)

	networkInfo, err := d.getNetwork(r.NetworkID)
	endpointInfo, err := networkInfo.getEndpoint(r.EndpointID)

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

	return nil
}

// DiscoverNew is not used by local scoped drivers
func (d *Driver) DiscoverNew(r *dockerSdk.DiscoveryNotification) error {
	return nil
}

// DiscoverDelete is not used by local scoped drivers
func (d *Driver) DiscoverDelete(r *dockerSdk.DiscoveryNotification) error {
	return nil
}

func truncateID(id string) string {
	return id[:5]
}
