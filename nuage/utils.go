package nuage

import (
	"crypto/rand"
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
)

// Generate a mac addr
func makeMac() (net.HardwareAddr, error) {
	hw := make(net.HardwareAddr, 6)
	buf := make([]byte, 4)

	_, err := rand.Read(buf)
	if err != nil {
		fmt.Println("error:", err)
		return nil, err
	}

	hw[0] = 0x7a
	hw[1] = 0x42
	copy(hw[2:], buf)
	return hw, nil

}

// Increment a subnet
func ipIncrement(networkAddr net.IP) net.IP {
	for i := 15; i >= 0; i-- {
		b := networkAddr[i]
		if b < 255 {
			networkAddr[i] = b + 1
			for xi := i + 1; xi <= 15; xi++ {
				networkAddr[xi] = 0
			}
			break
		}
	}
	return networkAddr
}

// Check if a netlink interface exists in the default namespace
func validateHostIface(ifaceStr string) bool {
	_, err := net.InterfaceByName(ifaceStr)
	if err != nil {
		log.Debugf("The requested interface to delete [ %s ] was not found on the host: %s", ifaceStr, err)
		return false
	}
	return true
}

// parseIPNet returns a net.IP from a network cidr in string representation
func parseIPNet(s string) (*net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return &net.IPNet{IP: ip, Mask: ipNet.Mask}, nil
}
