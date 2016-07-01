# LibNetwork-Plugin


It works as follow:
you run the code from the above github on a Server with VRS and Docker Engine installed. It connects to the Libnetwork API and to the VRS API.


Concept:
This only works with recreated networks on the VSD.
On each servers, a new Libnetwork network needs to be created with the specific options needed to link it to the existing network on VSD. As follow from the CLI:
docker network create --driver=nuage -o enterprise=Enterprise -o domain=Domain -o zone=Zone -o subnet=Subnet -o user=User --subnet=10.107.54.0/24 b1


You need to give the CIDR That corresponds to the Subnet because as for now,the IPAM will be taken care by Libnetwork itself. The IP chosen will be added as a Bottom up Static-IP request.

This basically creates a local link ont he local server to the Network on VSD:

root@ubuntu:~# docker network ls
NETWORK ID          NAME                DRIVER
279a417467bc        b1                  nuage               
135a97da9c70        bridge              bridge              
e8436e588b3b        docker_gwbridge     bridge              
5715bd28b784        help                bridge              
7e51cd7c8901        host                host                
c595bf2c1e29        none                null                
root@ubuntu:~# 


then you can start containers, just by referencing the network (b1 in this case):

docker run -it --net b1 nginx /bin/bash

Here the magic happens and you can see the corresponding vPort being created on the VSD.
