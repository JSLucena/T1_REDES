#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define BUFFER_SIZE 1600
#define ETHERTYPE 0x0806

int main(int argc, char *argv[])
{
	int fd;
	unsigned char buffer[BUFFER_SIZE];
	unsigned char *data;
	struct ifreq ifr;
	char ifname[IFNAMSIZ];
	char target_ip[4];
	char my_ip[4];
	char optype;

	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	fd = socket(PF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
	if(fd < 0) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	strcpy(ifr.ifr_name, ifname);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	/* Obtem as flags da interface */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0){
		perror("ioctl");
		exit(1);
	}

	/* Coloca a interface em modo promiscuo */
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	printf("Esperando pacotes ... \n");
	while (1) {
		unsigned char mac_dst[6];
		unsigned char mac_src[6];
		short int ethertype;

		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
        
		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer+sizeof(mac_dst), sizeof(mac_src));
		memcpy(&ethertype, buffer+sizeof(mac_dst)+sizeof(mac_src), sizeof(ethertype));
		memcpy(&target_ip, buffer+28,4);
		memcpy(&my_ip, buffer+38,4);
		memcpy(&optype,buffer+21,1);
		ethertype = ntohs(ethertype);
		data = (buffer+sizeof(mac_dst)+sizeof(mac_src)+sizeof(ethertype));

		if (ethertype == ETHERTYPE) {
			if(optype == 2)
			{
				if(((my_ip[0] & 0xFF) == 192) && ((my_ip[1] & 0xFF) == 168) && ((my_ip[2] & 0xFF) == 15) && ((my_ip[3] & 0xFF) == 105))
				{
					//printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x    ", 
								//mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
					//printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
							//	mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
					//printf("IP: %u.%u.%u.%u\n", target_ip[0] & 0xFF ,target_ip[1] & 0xFF,target_ip[2] & 0xFF,target_ip[3] & 0xFF);
					
					printf("%u.%u.%u.%u at %02x:%02x:%02x:%02x:%02x:%02x\n", target_ip[0] & 0xFF ,target_ip[1] & 0xFF,target_ip[2] & 0xFF,target_ip[3] & 0xFF, 
								mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
					
				}
			}
		}
	}

	close(fd);
	return 0;
}
