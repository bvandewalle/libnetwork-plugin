package nuage

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/docker/distribution/uuid"
	sdk "github.com/docker/go-plugins-helpers/network"
	vrssdk "github.com/nuagenetworks/libvrsovsdb/api"
	"github.com/nuagenetworks/libvrsovsdb/api/entity"
	"github.com/nuagenetworks/libvrsovsdb/api/port"
	"github.com/nuagenetworks/libvrsovsdb/test/util"
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
	sdk.Driver
	sync.Mutex
	networks networkTable
}

// NewDriver creates a new Nuage Driver
func NewDriver(version string) (*Driver, error) {
	log.Println("NewDriver called")
	d := &Driver{
		networks: networkTable{},
	}
	return d, nil
}

// GetCapabilities tells libnetwork this driver is local scope
func (d *Driver) GetCapabilities() (*sdk.CapabilitiesResponse, error) {
	scope := &sdk.CapabilitiesResponse{Scope: sdk.LocalScope}
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
func (d *Driver) CreateNetwork(r *sdk.CreateNetworkRequest) error {

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
func (d *Driver) DeleteNetwork(r *sdk.DeleteNetworkRequest) error {
	log.Println("DeleteNetwork")
	d.deleteNetwork(r.NetworkID)
	return nil
}

// CreateEndpoint creates a new MACVLAN Endpoint
func (d *Driver) CreateEndpoint(r *sdk.CreateEndpointRequest) (*sdk.CreateEndpointResponse, error) {
	endID := r.EndpointID
	log.Printf("The container subnet for this context is [ %s ]", r.Interface.Address)
	// Request an IP address from libnetwork based on the cidr scope
	// TODO: Add a user defined static ip addr option in Docker v1.10
	containerAddress := r.Interface.Address
	if containerAddress == "" {
		return nil, fmt.Errorf("Unable to obtain an IP address from libnetwork default ipam")
	}
	// generate a mac address for the pending container
	mac := util.GenerateMAC()

	log.Printf("Allocated container IP: [ %s ]", containerAddress)
	log.Printf("Allocated container MAC: [ %s ]", r.Interface.MacAddress)
	log.Printf("Generated container MAC: [ %s ]", mac)
	// IP addrs comes from libnetwork ipam via user 'docker network' parameters

	res := &sdk.CreateEndpointResponse{
		Interface: &sdk.EndpointInterface{
			//Address:    containerAddress,
			MacAddress: mac,
		},
	}
	log.Printf("Create endpoint response: %+v", res)
	log.Printf("Create endpoint %s %+v", endID, res)

	ep := &endpoint{
		id:         endID,
		stringmac:  mac,
		stringaddr: containerAddress,
	}
	d.network(r.NetworkID).addEndpoint(ep)

	return res, nil
}

// DeleteEndpoint deletes a Nuage Endpoint
func (d *Driver) DeleteEndpoint(r *sdk.DeleteEndpointRequest) error {
	log.Printf("Delete endpoint request: %+v", &r)
	//TODO: null check cidr in case driver restarted and doesn't know the network to avoid panic
	log.Printf("Delete endpoint %s", r.EndpointID)
	return nil
}

// EndpointInfo returns informatoin about a Nuage endpoint
func (d *Driver) EndpointInfo(r *sdk.InfoRequest) (*sdk.InfoResponse, error) {
	log.Printf("Endpoint info request: %+v", &r)
	res := &sdk.InfoResponse{
		Value: make(map[string]string),
	}
	return res, nil
}

// Join creates a Nuage interface to be moved to the container netns
func (d *Driver) Join(r *sdk.JoinRequest) (*sdk.JoinResponse, error) {

	var vrsConnection vrssdk.VRSConnection
	var err error
	networkInfo, err := d.getNetwork(r.NetworkID)
	endpointInfo, err := networkInfo.getEndpoint(r.EndpointID)

	fmt.Println("Endpoint Info:")
	fmt.Println(endpointInfo)

	if vrsConnection, err = vrssdk.NewConnection("10.31.1.195", 6633); err != nil {
		fmt.Println("Unable to connect to the VRS")
	}

	vmInfo := make(map[string]string)
	vmInfo["name"] = fmt.Sprintf("Test-VM-%d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(100))
	vmInfo["mac"] = endpointInfo.stringmac
	vmInfo["vmuuid"] = uuid.Generate().String()
	vmInfo["entityport"] = internalPrefix + truncateID(r.EndpointID)
	vmInfo["brport"] = basePrefix + truncateID(r.EndpointID)
	portList := []string{vmInfo["entityport"], vmInfo["brport"]}
	err = util.CreateVETHPair(portList)
	if err != nil {
		fmt.Println("Unable to create veth pairs on VRS")
	}

	// Add the paired veth port to alubr0 on VRS
	err = util.AddVETHPortToVRS(vmInfo["brport"], vmInfo["vmuuid"], vmInfo["name"])
	if err != nil {
		fmt.Println("Unable to add veth port to alubr0")
	}

	// Create Port Attributes
	portAttributes := port.Attributes{
		Platform: entity.TypeKVM,
		MAC:      vmInfo["mac"],
		Bridge:   "alubr0",
	}

	// Create Port Metadata
	portMetadata := make(map[port.MetadataKey]string)
	portMetadata[port.MetadataKeyDomain] = networkInfo.nuage.Domain
	portMetadata[port.MetadataKeyNetwork] = networkInfo.nuage.NuageSubnetID
	portMetadata[port.MetadataKeyZone] = networkInfo.nuage.Zone
	portMetadata[port.MetadataKeyNetworkType] = "ipv4"
	portMetadata[port.MetadataKeyStaticIP] = endpointInfo.stringaddr[:len(endpointInfo.stringaddr)-3]

	// Associate one veth port to entity
	err = vrsConnection.CreatePort(vmInfo["entityport"], portAttributes, portMetadata)
	if err != nil {
		fmt.Printf("Unable to create entity port %v", err)
	}

	// Create VM metadata
	vmMetadata := make(map[entity.MetadataKey]string)
	vmMetadata[entity.MetadataKeyUser] = networkInfo.nuage.User
	vmMetadata[entity.MetadataKeyEnterprise] = networkInfo.nuage.Enterprise

	// Define ports associated with the VM
	ports := []string{vmInfo["entityport"]}

	// Add entity to the VRS
	// Add entity to the VRS
	entityInfo := vrssdk.EntityInfo{
		UUID:     vmInfo["vmuuid"],
		Name:     vmInfo["name"],
		Type:     entity.TypeKVM,
		Ports:    ports,
		Metadata: vmMetadata,
	}

	err = vrsConnection.AddEntity(entityInfo)
	if err != nil {
		fmt.Printf("Unable to add entity to VRS %v", err)
	}

	// Notify VRS that VM has completed booted
	err = vrsConnection.PostEntityEvent(vmInfo["vmuuid"], entity.EventCategoryStarted, entity.EventStartedBooted)

	if err != nil {
		fmt.Printf("Problem sending VRS notification %v", err)
	}

	// SrcName gets renamed to DstPrefix on the container iface
	ifname := &sdk.InterfaceName{
		SrcName:   vmInfo["entityport"],
		DstPrefix: containerIfacePrefix,
	}

	res := &sdk.JoinResponse{
		InterfaceName: *ifname,
		//Gateway:               getID.gateway,
		DisableGatewayService: true,
	}
	log.Printf("Join response: %+v", res)
	log.Printf("Join endpoint %s:%s to %s", r.NetworkID, r.EndpointID, r.SandboxKey)
	return res, nil
}

// Leave removes a Nuage Endpoint from a container
func (d *Driver) Leave(r *sdk.LeaveRequest) error {
	log.Printf("Leave request: %+v", &r)
	log.Printf("Leave %s:%s", r.NetworkID, r.EndpointID)

	return nil
}

// DiscoverNew is not used by local scoped drivers
func (d *Driver) DiscoverNew(r *sdk.DiscoveryNotification) error {
	return nil
}

// DiscoverDelete is not used by local scoped drivers
func (d *Driver) DiscoverDelete(r *sdk.DiscoveryNotification) error {
	return nil
}

func truncateID(id string) string {
	return id[:5]
}
