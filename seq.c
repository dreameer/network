/*
* Example of using TCP raw sockets on FreeBSD 4.x and 5.x maybe other too.
* Written for educational purposes by Clau & Burebista
*
* www.reversedhell.net
* clau: clau@reversedhell.net, dr.clau@xnet.ro
* burebista: aanton@reversedhell.net, uber@rdslink.ro
*
* We both worked equally hard studying the headers, the sources of the
* system and of other programs, thus the order of precedence in the
* credit field is completely random.
*
* I, burebista, would like to thank the freebsd-hackers mailing list for
* their help regarding header includes.
*
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define PORT 80
#define INTERFACE "ed0"
#define debug 
/*
* bpf_open()
*
* opens the first available /dev/bpf device
* and returns the file descriptor
*
*/
int bpf_open() {
       	char dev[] = "/dev/bpf";
       	char num[2], buf[11];
       	int i, fd;
       	fd = -1;
       	i = 0;
       	do {
	       	sprintf((char *) &buf, "%s%u", dev, i);
	       	fd = open((char *) &buf, O_RDWR);
	       	i++;
       	} while(fd < 0 && i < 10);
#ifdef debug
       	printf("bpf_open:\t%s\n", buf);
#endif
       	return fd;
}
/*
* seq_read
*
* sip - source IP for filter
* dip - destination IP for filter
* sport - source port for filter
* dport - destination port for filter
* (all in host byteorder)
*/
int seq_read(int fd, int sip, int dip, short sport, short dport) {
       	int true = 1;
       	int buflen, r;
       	struct bpf_hdr *buf;
       	struct ifreq ifreq;
       	struct bpf_insn insns[] = {
	       	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	       	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 11),
	       	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
	       	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 6, 0, 9),
	       	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
	       	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sip, 0, 7),
	       	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
	       	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, dip, 0, 5),
	       	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 34),
	       	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sport, 0, 3),
	       	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 36),
	       	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, dport, 0, 1),
	       	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
	       	BPF_STMT(BPF_RET+BPF_K, 0),
       	};
       	struct bpf_program bpf_program = {
	       	14,
	       	(struct bpf_insn *) &insns
       	};
       	struct timeval timeval;
       	struct ip *iph;
       	struct tcphdr *tcph;
       	strcpy((char *) ifreq.ifr_name, INTERFACE);
       	if (ioctl(fd, BIOCSETIF, &ifreq) < 0) {
	       	perror("ioctl BIOCSETIF");
	       	return -1;
       	}
       	ioctl(fd, BIOCGBLEN, &buflen);
       	if (ioctl(fd, BIOCIMMEDIATE, (u_int) &true) < 0) {
	       	perror("BIOCIMMEDIATE");
	       	return -1;
       	}
       	timeval.tv_sec = 5;
       	timeval.tv_usec = 0;
       	if (ioctl(fd, BIOCSRTIMEOUT, (struct timeval *) &timeval) < 0) {
	       	perror("set timeout");
	       	return -1;
       	}
       	if (ioctl(fd, BIOCSETF, (struct bpf_program *) &bpf_program) < 0) {
	       	perror("set filter");
	       	return -1;
       	}
       	buf = (struct bpf_hdr *)malloc(buflen);
       	bzero(buf, buflen);
       	r = read(fd, buf, buflen);
       	iph = (struct ip *) ((char *) buf + buf->bh_hdrlen + sizeof(struct ether_header));
       	tcph = (struct tcphdr *) ((char *) iph + sizeof(struct ip));
#ifdef debug
       	printf("IP SRC:\t\t%s\n", inet_ntoa(iph->ip_src));
       	printf("IP DST:\t\t%s\n", inet_ntoa(iph->ip_dst));
       	printf("TCP SRC:\t%u\n", ntohs(tcph->th_sport));
       	printf("TCP DST:\t%u\n", ntohs(tcph->th_dport));
       	printf("SEQ #:\t\t%u\n", ntohl(tcph->th_seq));
#endif
       	if (r > 0)
	       	return ntohl(tcph->th_seq);
       	return 0;
}
unsigned short in_cksum(unsigned short *addr, int len)
{
       	register int sum = 0;
       	u_short answer = 0;
       	register u_short *w = addr;
       	register int nleft = len;
       	while (nleft > 1)
       	{
	       	sum += *w++;
	       	nleft -= 2;
       	}
       	if (nleft == 1)
       	{
	       	*(u_char *) (&answer) = *(u_char *) w;
	       	sum += answer;
       	}
       	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16); answer = ~sum;
       	return (answer);
}
int main (void) {
       	int bpf = bpf_open(); /* open /dev/bpfX */
       	int s = socket (PF_INET, SOCK_RAW, IPPROTO_IP); /* open raw socket */
	printf("sock protol %d\n",IPPROTO_IP);
	int addr_len,i,oldisn=0,newisn,one=1; const int *val = &one;
	struct timeval tv1,tv2; struct timezone tz1,tz2;
       	char datagram[4096]; /* datagram buffer */
       	char pseudohdr[1024]; /* pseudoheader buffer for computing tcp checksum */
       	struct ip *iph = (struct ip *) datagram;
       	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
       	struct sockaddr_in sin;
       	struct sockaddr_in sout;
	int tcphdr_size = sizeof(struct tcphdr); sin.sin_family = AF_INET;
       	sin.sin_family = AF_INET;
       	sin.sin_port = htons (PORT);
	sin.sin_addr.s_addr = inet_addr ("220.181.38.148"); /* destination ip */ memset(datagram, 0, 4096); /* zero out the buffer */
       	/* we'll now fill in the ip/tcp header values, see above for explanations */
	iph->ip_hl = 5; iph->ip_v = 4;
       	iph->ip_tos = 0;
       	iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr); /* data size = 0 */
       	iph->ip_id = htons (31337);
       	iph->ip_off = 0;
       	iph->ip_ttl = 250;
       	iph->ip_p = 6;
       	iph->ip_sum = 0;
       	iph->ip_src.s_addr = inet_addr ("10.1.3.31");/* source ip (me!) */
       	iph->ip_dst.s_addr = sin.sin_addr.s_addr;
       	tcph->th_sport = htons (1234); /* source port */
       	
	tcph->th_dport = htons (PORT); /* destination port */ tcph->th_seq = htonl(31337);
       	tcph->th_ack = 0;/* in first SYN packet, ACK is not present */
       	tcph->th_x2 = 0;
       	tcph->th_off = sizeof(struct tcphdr)/4; /* data position in the packet */
       	tcph->th_flags = TH_SYN; /* initial connection request */
       	tcph->th_win = htons (57344); /* FreeBSD uses this value too */
       	tcph->th_sum = 0; /* we will compute it later */
       	tcph->th_urp = 0; 
	if (tcphdr_size % 4 != 0){ /* takes care of padding to 32 bits */
	       	tcphdr_size = ((tcphdr_size % 4) + 1) * 4;
	}
#ifdef debug
       	printf("packet size:\t%u\n", tcphdr_size);
#endif
       	/* create the pseudo header
	 * *
	 * * +--------+--------+--------+--------+
	 * * | Source Address |
	 * * +--------+--------+--------+--------+
	 * * | Destination Address |
	 * * +--------+--------+--------+--------+
	 * * | zero | PTCL | TCP Length |
	 * * +--------+--------+--------+--------+

	 *
	 * * The TCP Length is the TCP header length plus the data length in
	 * * octets (this is not an explicitly transmitted quantity, but is
	 * * computed), and it does not count the 12 octets of the pseudo
	 * * header.
	 * */
       	memset(pseudohdr,0x0,sizeof(pseudohdr));
       	memcpy(&pseudohdr,&(iph->ip_src.s_addr),4);
       	memcpy(&pseudohdr[4],&(iph->ip_dst.s_addr),4);
       	pseudohdr[8]=0; // just to underline this zero byte specified by rfc
       	pseudohdr[9]=(u_int16_t)iph->ip_p; pseudohdr[10]=(u_int16_t)(tcphdr_size&0xFF00)>>8;
       	pseudohdr[11]=(u_int16_t)(tcphdr_size&0x00FF);
       	memcpy(&pseudohdr[12], tcph, sizeof(struct tcphdr));
       	/*
	 * *end of pseudo header part
	 * */
       	tcph->th_sum = in_cksum((unsigned short*)(pseudohdr),tcphdr_size+12);
#ifdef debug
       	printf ("IP checksum set to : %hu\n",ntohs(iph->ip_sum));
       	printf ("TCP checksum set to : %hu\n",ntohs(tcph->th_sum));
#endif
       	printf("s %d\n",s);
       	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
	       	printf ("Warning: Cannot set HDRINCL!\n"); }
       	fprintf(stderr," DIF ISN RRT(usec)\n");
       	printf("%d %ld %ld \n",iph->ip_len,sizeof(datagram),sizeof(sin));
       	for (i=0;i<=9;i++)
       	{
	       	if (sendto (s,(const void*)datagram,iph->ip_len,0,(struct sockaddr *)&sin, sizeof (sin)) < 0)
	       	{
		       	printf("i %d ,errno %d\n",i,errno);
		       	perror ("sendto");
		       	exit(1);
	       	}
	       	gettimeofday(&tv1,&tz1);
	       	newisn=seq_read(bpf,
			       	ntohl(iph->ip_dst.s_addr),
			       	ntohl(iph->ip_src.s_addr),
			       	ntohs(tcph->th_dport),
			       	ntohs(tcph->th_sport));
	       	if (newisn==0) {
		       	fprintf(stderr,"\nOperation timed out!\n\n");
		       	close(s);
		       	close(bpf);
		       	exit(1);
	       	}
	       	if (i==0){
		       	fprintf(stderr,"---------- %10u ",newisn);
		}
	       	else{
		       	fprintf(stderr,"%10u %10u ",newisn-oldisn,newisn);
		}
	       	gettimeofday(&tv2,&tz2);
	       	fprintf(stderr,"%ld\n",((tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec)));
	       	oldisn=newisn;
	       	/* time is measured in microseconds */
       	}
       	close(s);
       	close(bpf);
       	return 0;
}
