#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	int byte = 0;
	char buffer[BUFFER_SIZE];
	//char data[MAX_DATA_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	//char dest_mac[] = {0xD8, 0xCB, 0x8A, 0x3C, 0x0C, 0x18};
	char orig_ip[] = {192, 168, 15, 105};
	char dest_ip[] = {192, 168, 15, 17};
	short int ethertype = htons(0x0806);
	char ARP_header[8] = {0,1, 0x08, 0x00, 6, 4, 0 , 1};

	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);


	/* Preenche o header ARP */
	memcpy(buffer + frame_len, ARP_header, sizeof(ARP_header));
	frame_len += sizeof(ARP_header);

	/* preenche mac do sender */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* preenche ip do sender */
	memcpy(buffer + frame_len, orig_ip, 4);
	frame_len += 4;

	/* zera mac do target */
	memset(buffer + frame_len, 0, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* preenche ip do target */
	memcpy(buffer + frame_len, dest_ip, 3);
	frame_len += 3;
	for(int i = 1; i < 255;i++)
	{
		char last_ip = i;
		memcpy(buffer + frame_len,&last_ip,1);
		frame_len++;


		//printf("Frame length: %d\n", frame_len);

		//int i =0;
		/*
		for(i = 0; i < frame_len;i++)
		{
			printf("%u\n",buffer[i] & 0xFF );
		}	
		*/

		/* Envia pacote */
		if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
			perror("send");
			close(fd);
			exit(1);
		}

		printf("Pacote enviado.\n");
		frame_len--;
	}

	close(fd);
	return 0;
}
