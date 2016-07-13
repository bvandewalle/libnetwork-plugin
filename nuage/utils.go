package nuage

import (
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
)

const (
	addCli    = "add"
	deleteCli = "del"
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

func ipIncrement(originalIP net.IP) (resultIP net.IP, err error) {
	ip := originalIP.To4()
	if ip == nil {
		return nil, fmt.Errorf("Error Converting Gateway IP")
	}
	ip[3]++
	return ip, nil
}

// Increment a subnet
func netIncrement(networkAddr net.IP) net.IP {
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

// CreateVETHPair will help user create veth pairs to associate
// with a VM or a Container
func createVETHPair(portList []string) error {

	cmdstr := fmt.Sprintf("ip link %s %s type veth peer name %s", addCli, portList[0], portList[1])
	cmd := exec.Command("bash", "-c", cmdstr)
	_, err := cmd.Output()

	if err != nil {
		return fmt.Errorf("Error while creating veth pair on VRS %v", err)
	}

	for index := range portList {
		cmdstr = fmt.Sprintf("ip link set dev %s up", portList[index])
		cmd = exec.Command("bash", "-c", cmdstr)
		_, err = cmd.Output()

		if err != nil {
			return fmt.Errorf("Error while bringing up veth interface on VRS %v", err)
		}
	}

	return nil
}

// DeleteVETHPair will help user delete veth pairs on VRS
func deleteVETHPair(entityPort string, brPort string) error {

	cmdstr := fmt.Sprintf("ip link %s %s type veth peer name %s", deleteCli, entityPort, brPort)
	cmd := exec.Command("bash", "-c", cmdstr)
	_, err := cmd.Output()

	if err != nil {
		return fmt.Errorf("Error while creating veth pair on VRS %v", err)
	}

	return nil
}

// AddVETHPortToVRS will help add veth ports to VRS alubr0
func addVETHPortToVRS(port string, vmuuid string, vmname string) error {

	cmdstr := fmt.Sprintf("/usr/bin/ovs-vsctl --no-wait --if-exists del-port alubr0 %s -- %s-port alubr0 %s -- set interface %s 'external-ids={vm-uuid=%s,vm-name=%s}'", port, addCli, port, port, vmuuid, vmname)
	cmd := exec.Command("bash", "-c", cmdstr)
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Problem adding veth port to alubr0 on VRS %v", err)
	}

	return nil
}

// RemoveVETHPortFromVRS will help delete veth ports from VRS alubr0
func removeVETHPortFromVRS(port string) error {

	cmdstr := fmt.Sprintf("/usr/bin/ovs-vsctl --no-wait %s-port alubr0 %s", deleteCli, port)
	cmd := exec.Command("bash", "-c", cmdstr)
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Problem deleting veth port from alubr0 on VRS %v", err)
	}

	return nil
}
