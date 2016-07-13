# LibNetwork-Plugin

This is an Experimental Nuage plugin for LibNetwork.
It allows the user to create new Networks of Type Nuage by using Docker Network/Libnetwork.

The driver supports both local and global Networks.

# Concept

The new Networks of Type Nuage in LibNetwork are implemented in the backend by a specific Subnet in VSD.
A specific Libnetwork Network (Docker network ...) needs to reference a specific Subnet from VSD. This is done by giving extra-parameters to LibNetwork at Network creation time.

The user interacts with Docker Network, which calls Libnetwork ans Nuage plugin. Nuage implement in the backend the requests coming from the user.

# Setup

This code connects to the remote JSON-RPC plugin API from Docker through the docker plugin .sock
It implements the standard LibNetwork API through that socket.

In order to run this plugin, there is the need to open an OVSDB connection to the VRS (This will be restricted to a file .sock in an upcoming version). In order to allow this on each VRS, the following command is required before starting the plugin. This is only required once on each VRS: Another port than 6633 can be chosen, in which case the config file for the plugin needs to reflect that.

'''
bvandewa$ ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6633
'''

All the parameters are specified in a config file. By default that file is in 'nuage.cfg' in the same directory as the executable. An alternate file can be provided by a specific argument to the executable:

'''
bvandewa$ ./plugin -f /etc/nuage/config.cfg
'''

The configuration file follows the following format, with the following default value:

'''
VrsEndpoint = "localhost"
VrsPort = 6633
VrsBridge = "alubr0"
DockerEndpoint = "unix:///var/run/docker.sock"
LogLevel = "Info" // Debug for more info
Scope = "global"  // global for MH or local for Single Host
'''

For a typical use-case, none of those values should have the need to be modified.

Upon starting, the plugin will connect to the Docker Daemon on the plugin socket, and on the local Nuage VRS.

# Single Host Networking
The Scope defines if your network is going to propagate to all the nodes part of your Cluster.
The simplest use case is for Single Host Networking. That translates to networks that are only visible on the host on which the Network is added.
This use-case is configured with the configuration Scope="local".

After starting the plugin, Docker API is used to create a network:

'''
root@ubuntu:~# docker network create --driver=nuage -o organization=Enterprise -o domain=Domain -o zone=Zone -o subnet="Subnet 2" -o user=admin --subnet=10.21.59.0/24  MyNet
'''

to link to a L3Domain in Nuage, the following parameters are required: enterprise,user,domain,zone,subnet.
Furthermore, the CIDR and IPAM information must be exactly the same as in Nuage. See IPAM considerations below.

Once the network is created, it can be seen and inspected:

'''
root@ubuntu:~# docker network ls
NETWORK ID          NAME                DRIVER
e793da0854ce        MyNet               nuage               
4d7098beb610        bridge              bridge              
cf0626f73c7c        docker_gwbridge     bridge              
b8878a9f9d58        host                host                
967ad3ccb5af        none                null  
'''

'''
root@ubuntu:~# docker network inspect MyNet
[
    {
        "Name": "MyNet",
        "Id": "8f8127c363669e8b2c07c5025386a574cbab23a194267bdc6b8d5e54658a8985",
        "Scope": "global",
        "Driver": "nuage",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.21.59.0/24"
                }
            ]
        },
        "Internal": false,
        "Containers": {
            "524fbb401c8c6f760e1e66f8be42f603e258c5c7a3807a7f66afa0a1b760295f": {
                "Name": "tender_goldstine",
                "EndpointID": "2b4fb640e6299ae5e00f7cbebebbef112490813cb57cd05a2e9fde5316208076",
                "MacAddress": "7a:42:d6:aa:d0:11",
                "IPv4Address": "10.21.59.2/24",
                "IPv6Address": ""
            },
            "ep-20b306d0998b227289a86ee4b6a69b4171d3dca666b1fe78cdcf5df4c1f86b89": {
                "Name": "thirsty_bassi",
                "EndpointID": "20b306d0998b227289a86ee4b6a69b4171d3dca666b1fe78cdcf5df4c1f86b89",
                "MacAddress": "7a:42:8d:fa:16:f3",
                "IPv4Address": "10.21.59.3/24",
                "IPv6Address": ""
            }
        },
        "Options": {
            "domain": "Domain",
            "organization": "Enterprise",
            "subnet": "Subnet 2",
            "user": "admin",
            "zone": "Zone"
        },
        "Labels": {}
    }
]
'''

To start a Container with access to that network, the network name needs to be referenced during Container definition:

'''
docker run -it --net MyNet nginx /bin/bash
'''

This will trigger the creation of a vPort on Nuage, and the vPort should be visible and fully manageable from VSD API.

In this use case, the Network is only visible on this specific server. Reachability can be extended by "creating" that same network on multiple nodes.

# Multi Host Networking

MultiHost Networking uses a backend store in order to propagate network information to all the cluster participants. As such, a network added on one node will be available on all the nodes.

In order to run multiHost networking, the Multiple Docker-Engines need to be started with a backend-Store, for example Consul:

On Host1:
'''
root@server1:~# docker daemon -D --cluster-store=consul://$CONSULSERVER:8500 --cluster-advertise=$server1:2376
'''

On Host2:
'''
root@server2:~# docker daemon -D --cluster-store=consul://$CONSULSERVER:8500 --cluster-advertise=$server2:2376
'''

When creating Network on node1:

'''
root@server1~# docker network create --driver=nuage -o organization=Enterprise -o domain=Domain -o zone=Zone -o subnet="Subnet 2" -o user=admin --subnet=10.21.59.0/24  MyNet
'''

That network is now available and ready for consumption on node2:


'''
root@server2:~# docker network ls
NETWORK ID          NAME                DRIVER
e793da0854ce        MyNet               nuage               
4d7098beb610        bridge              bridge              
cf0626f73c7c        docker_gwbridge     bridge              
b8878a9f9d58        host                host                
967ad3ccb5af        none                null  
'''

# IPAM considerations
IPAM is fully managed by Docker (Eventually, Nuage will also implement an IPAM Driver), which means that the CIDR and IP information associated to the Docker Network MUST reflect the Network information in VSD.
All the IPs for each Endpoints are assigned by Docker built-in IPAM and are pushed Statically to Nuage.
If there is the need to have non-docker endpoints in the same subnet in Nuage as the Docker endpoints, one solution is to use IPAM-Ranges to make sure that the IPs assigned by

# Roadmap and improvements
- Add PolicyGroup tag for Containers (Probably using a Label)
