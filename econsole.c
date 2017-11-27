/*
 * File: econsole.c
 * Implements: ethernet console client
 *
 * Copyright: Jens Låås, 2011
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <stdio.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <poll.h>

#include <termios.h> /* for tcgetattr */
#include <sys/ioctl.h> /* for winsize */
#include <signal.h>

#include <time.h>

#include <net/if.h>

#include "egetty.h"
#include "skbuff.h"
#include "jelopt.h"

struct {
	int debug;
	int console;
	int devsocket;
	int scan;
	int devices;
	int push;
	int shell;
	int ucast;
	int row, col;
	int s;
	int ifindex;
	
	struct sockaddr_ll dest;
	
	struct termios term;
} conf;

static int send_ucast(int s,int ifindex,struct sockaddr_ll *mac,struct sk_buff *skb)
{
	struct sockaddr_ll dest;
	socklen_t destlen = sizeof(dest);
	int rc;

	memset(&dest, 0, sizeof(dest));

	dest.sll_family = AF_PACKET;
	dest.sll_halen = 6;
	dest.sll_protocol = htons(ETH_P_EGETTY);
	dest.sll_ifindex = ifindex;
	memcpy(dest.sll_addr, mac->sll_addr, 6);
	
	rc = sendto(s, skb->data, skb->len, 0, (const struct sockaddr *)&dest, destlen);
	if(rc == -1) {
		return -1;
	}
	if(conf.debug) {
		int i;
		printf("sent %d bytes to ", skb->len);
		for(i=0;i<6;i++)
			printf("%02x%s", dest.sll_addr[i], i==5?"":":");
		printf("\n");
	}
	return 0;
}

static int console_send(int s, int ifindex, struct sk_buff *skb)
{
	struct sockaddr_ll dest;
	socklen_t destlen = sizeof(dest);
	int rc;

	memset(&dest, 0, sizeof(dest));

	dest.sll_family = AF_PACKET;
	dest.sll_halen = 6;
	dest.sll_protocol = htons(ETH_P_EGETTY);
	dest.sll_ifindex = ifindex;
	if(conf.ucast)
		memcpy(dest.sll_addr, conf.dest.sll_addr, 6);
	else
		memset(dest.sll_addr, 255, 6);
	
	rc = sendto(s, skb->data, skb->len, 0, (const struct sockaddr *)&dest, destlen);
	if(rc == -1) {
		return -1;
	}
	if(conf.debug) {
		int i;
		printf("sent %d bytes to ", skb->len);
		for(i=0;i<6;i++)
			printf("%02x%s", dest.sll_addr[i], i==5?"":":");
		printf("\n");
	}
	return 0;
}

static int console_put(int s, int ifindex, struct sk_buff *skb)
{
	int rc;
	uint8_t *p;

	p = skb_push(skb, 4);
	*p++ = EGETTY_IN;
	*p++ = conf.console;
	*p++ = skb->len >> 8;
	*p = skb->len & 0xff;
	
	rc = console_send(s, ifindex, skb);
	if(rc == -1) {
		printf("sendto failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int console_winch(int s, int ifindex, int row, int col)
{
	int rc;
	uint8_t *p;
	struct sk_buff *skb = alloc_skb(64);

	p = skb_put(skb, 0);
	*p++ = EGETTY_WINCH;
	*p++ = conf.console;
	*p++ = row;
	*p++ = col;
	p = skb_put(skb, 4);
	
	rc = console_send(s, ifindex, skb);
	if(rc == -1) {
		printf("sendto failed: %s\n", strerror(errno));
		free_skb(skb);
		return -1;
	}
	free_skb(skb);
	return 0;
}

static int console_hup(int s, int ifindex)
{
	int rc;
	uint8_t *p;
	struct sk_buff *skb = alloc_skb(64);

	p = skb_put(skb, 0);
	*p++ = EGETTY_HUP;
	*p++ = conf.console;
	p = skb_put(skb, 2);
	
	rc = console_send(s, ifindex, skb);
	if(rc == -1) {
		printf("sendto failed: %s\n", strerror(errno));
		free_skb(skb);
		return -1;
	}
	free_skb(skb);
	return 0;
}

static void winch_handler(int sig)
{
	struct winsize winp;

	if(!ioctl( 0, TIOCGWINSZ, &winp))
	{
		conf.row = winp.ws_row;
		conf.col = winp.ws_col;
		console_winch(conf.s, conf.ifindex, conf.row, conf.col);
	}
}

static int signals_init()
{
	static struct sigaction act;
	int rc = 0;

	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_handler = winch_handler;
	act.sa_flags = 0;
	rc |= sigaction(SIGWINCH, &act, NULL);

	return rc;
}

static int terminal_settings()
{
	struct termios term;
	
	tcgetattr(0, &conf.term);
	
	if(tcgetattr(0, &term))
		if(conf.debug) fprintf(stderr, "ERROR tcgetattr!\n");
	
	term.c_lflag &= ~ICANON;
	term.c_lflag &= ~ECHO;
	term.c_lflag &= ~ISIG;

        term.c_iflag |= IGNPAR;
        term.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUCLC
        term.c_iflag &= ~IUCLC;
#endif
        term.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
#ifdef IEXTEN
        term.c_lflag &= ~IEXTEN;
#endif
        term.c_oflag &= ~OPOST;
	
	return tcsetattr(0, TCSANOW, &term);
}

static int devsocket(void)
{
	/* we couldn't care less which one; just want to talk to the kernel! */
	static int dumb[3] = { AF_INET, AF_PACKET, AF_INET6 };
	int i, fd;
  
	for(i=0; i<3; i++)
		if((fd = socket(dumb[i], SOCK_DGRAM, 0)) >= 0)
			return fd;
	return -1;
}


/* Set a certain interface flag. */
static int set_flag(char *ifname, short flag)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	
	strcpy(ifr.ifr_name, ifname);
	
	if (ioctl(conf.devsocket, SIOCGIFFLAGS, &ifr) < 0) {
		return -1;
	}
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_flags |= flag;
	if (ioctl(conf.devsocket, SIOCSIFFLAGS, &ifr) < 0) {
		return -1;
	}
	return 0;
}

static int send_bcast(int s, int ifindex, struct sk_buff *skb)
{
	struct sockaddr_ll dest;
	socklen_t destlen = sizeof(dest);

	memset(&dest, 0, sizeof(dest));

	dest.sll_family = AF_PACKET;
	dest.sll_halen = 6;
	dest.sll_protocol = htons(ETH_P_EGETTY);
	dest.sll_ifindex = ifindex;
	memset(dest.sll_addr, 255, 6);
	
	return sendto(s, skb->data, skb->len, 0, (const struct sockaddr *)&dest, destlen);
}

static int console_scan(int s, int ifindex, struct sk_buff *skb)
{
	int rc;
	uint8_t *p;

	p = skb_push(skb, 4);
	*p++ = EGETTY_SCAN;
	*p++ = conf.console;
	*p++ = skb->len >> 8;
	*p = skb->len & 0xff;
	
	rc = send_bcast(s, ifindex, skb);
	if(rc == -1) {
		fprintf(stderr, "sendto failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void timespec_diff(struct timespec *start, struct timespec *stop, struct timespec *result)
{
	if ((stop->tv_nsec - start->tv_nsec) < 0) {
		result->tv_sec = stop->tv_sec - start->tv_sec - 1;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
	} else {
		result->tv_sec = stop->tv_sec - start->tv_sec;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

	return;
}

//Returns the seconds passed from given ts
static int seconds_elapsed_from(struct timespec *ts)
{
	struct timespec now_ts,diff_ts;
	clock_gettime(CLOCK_MONOTONIC_RAW,&now_ts);
	
	timespec_diff(ts,&now_ts,&diff_ts);
	
	return diff_ts.tv_sec;
	
}

static int console_devices(int s, int ifindex, struct sk_buff *skb,struct sockaddr_ll *res)
{
	int rc;
	uint8_t *buf, *p;
	int n;
	struct timespec start_ts;
	struct sockaddr_ll from;
	socklen_t fromlen = sizeof(from);
	int i;
	unsigned int len;
	int rec_n;
	
	if (res == NULL){
		res = &from;
	}
	
	p = skb_push(skb, 4);
	*p++ = EGETTY_SCAN;
	*p++ = conf.console;
	*p++ = skb->len >> 8;
	*p = skb->len & 0xff;
	
	rc = send_bcast(s, ifindex, skb);
	if(rc == -1) {
		fprintf(stderr, "sendto failed: %s\n", strerror(errno));
		return -1;
	}
	
	struct pollfd fds[1];
	fds[0].fd = conf.s;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	
	clock_gettime(CLOCK_MONOTONIC_RAW,&start_ts);
	
	while(1){
		if (conf.debug)
			printf("polling... \n");
		n = poll(fds,1,3000);
		if (conf.debug)
			printf("Got polled by: %d \n",n);
		if (seconds_elapsed_from(&start_ts) > 3){//Time Elapsed
			break;
		}
		
		if (n == 1){
			skb_reset(skb);
			buf = skb_put(skb, 0);
			rec_n = recvfrom(conf.s, buf, skb_tailroom(skb), 0, (struct sockaddr *)res, &fromlen);
			if(rec_n == -1) {
				fprintf(stderr, "recvfrom() failed. ifconfig up?\n");
				continue;
			}
			skb_put(skb, rec_n);

			if(conf.ucast)
				if(memcmp(conf.dest.sll_addr, res->sll_addr, 6))
					continue;
		
			if(ntohs(from.sll_protocol) == ETH_P_EGETTY) {
				if(conf.debug) printf("Received EGETTY\n");
				p = skb->data;
				if(*p == EGETTY_HELLO) {
						p++;
						printf("Console: %d ", *p);
						for(i=0;i<6;i++)
							printf("%02x%s", res->sll_addr[i], i==5?"":":");
						printf("\n");
					continue;
				}
			}
			
		}else if (n == 0){//Timeout
			break;
		}
		
		
	}
	console_hup(conf.s, conf.ifindex);
	//tcsetattr(0, TCSANOW, &conf.term);
	
	//printf("Exiting devices \n");
	return 0;
}

static int console_shell(int s, int ifindex, struct sk_buff *skb)
{
	int n;
	int poll_n; 
	uint8_t *buf, *p;
	int i;
	struct sockaddr_ll from;
	socklen_t fromlen = sizeof(from);
	unsigned int len;
	int rc;
	
	
	rc = send_bcast(s, ifindex, skb);
	if(rc == -1) {
		fprintf(stderr, "sendto failed: %s\n", strerror(errno));
		return -1;
	}
	
	while(1){
		struct pollfd fds[2];

		fds[0].fd = 0;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		
		fds[1].fd = conf.s;
		fds[1].events = POLLIN;
		fds[1].revents = 0;

		poll_n = poll(fds, 2, -1);
		if(poll_n == 0) {
			printf("timeout\n");
			continue;
		}

		if(fds[0].revents & POLLIN) {
			skb_reset(skb);
			skb_reserve(skb, 4);
			buf = skb_put(skb, 0);
			n = read(0, buf, skb_tailroom(skb));
			if(n == -1) {
				fprintf(stderr, "read() failed\n");
				exit(1);
			}
			if(n == 0) {
				fprintf(stderr, "read() EOF\n");
				exit(0);
			}
			buf[n] = 0;
			if(conf.debug) printf("read %d bytes from stdin\n", n);
			if(conf.debug > 1) printf("buf[0] == %d\n", buf[0]);
			if(n==1 && buf[0] == 0x1d) {
				console_hup(conf.s, conf.ifindex);
				tcsetattr(0, TCSANOW, &conf.term);
				exit(0);
			}
			skb_put(skb, n);
			if(!conf.scan) console_put(conf.s, conf.ifindex, skb);
		}
		
		if(fds[1].revents) {
			skb_reset(skb);
			buf = skb_put(skb, 0);
			n = recvfrom(conf.s, buf, skb_tailroom(skb), 0, (struct sockaddr *)&from, &fromlen);
			if(n == -1) {
				fprintf(stderr, "recvfrom() failed. ifconfig up?\n");
				continue;
			}
			skb_put(skb, n);

			if(conf.ucast)
				if(memcmp(conf.dest.sll_addr, from.sll_addr, 6))
					continue;
			
			if(ntohs(from.sll_protocol) == ETH_P_EGETTY) {
				if(conf.debug) printf("Received EGETTY\n");
				p = skb->data;
				if(*p == EGETTY_HELLO) {
					if(conf.scan) {
						p++;
						printf("Console: %d ", *p);
						for(i=0;i<6;i++)
							printf("%02x%s", from.sll_addr[i], i==5?"":":");
						printf("\n");
					}
					continue;
				}
				if(*p == EGETTY_OUT || *p == EGETTY_KMSG) {
					p++;
					if(*p++ != conf.console) continue;
					len = *p++ << 8;
					len += *p;
					skb_trim(skb, len);
					skb_pull(skb, 4);
					if(!conf.scan) write(1, skb->data, skb->len);
				}
				continue;
			}
		}
		
	}
}

static char* get_dirstop(const char*  path )
{
    char*  p  = strrchr(path, '/');
    char*  p2 = strrchr(path, '\\');

    if ( !p )
        p = p2;
    else if ( p2 && p2 > p )
        p = p2;

    return p;
}

static const char* get_basename(const char* filename)
{
    const char* basename = get_dirstop(filename);
    if (basename) {
        basename++;
        return basename;
    } else {
        return filename;
    }
}

static long get_filesize(const char* file)
{
	FILE* fp = fopen(file, "r");
	if (fp == NULL){
		return -1;
	}
	fseek(fp, 0 , SEEK_END);
	long fileSize = ftell(fp);
	fclose(fp);
	
	return fileSize;
}


static int do_push_func(int s, int ifindex, struct sk_buff *skb,char *filename,char *dest_path)
{
	int rc;
	uint8_t *buf, *p;
	int n;
	struct timespec start_ts;
	struct sockaddr_ll from;
	socklen_t fromlen = sizeof(from);
	int i;
	unsigned int len;
	int rec_n;
	int ret = 0;
	int k =0;
	uint8_t file_len;
	uint8_t dest_path_len;
	uint64_t total_file_size;
	
	FILE *fp;
	char fb_buf[1024];
	char *file_basename;
	
	//First we want to check our file 
	total_file_size = get_filesize(filename);
	if (total_file_size < 0){
		printf("Could not stat file: %s \n",filename);
		return -1;
	}
	
	fp = fopen(filename, "r");
	if (fp == NULL){
		printf("Could not open file: %s for reading \n",filename);
		return -1;
	}
	printf("kkx \n");
	file_basename = get_basename(filename);
	printf("basename: %s \n", file_basename);
	

	//Second we want to check if our device exists:
	ret = console_devices(s,ifindex,skb,&from);
	if (ret != 0){
		printf("Could not find device on specified interface\n");
		return -1;
	}
	
	printf("Device found \n");
	sleep(1);
	printf("Sending EGETTY_PUSH_START \n");
	
	file_len = (uint8_t)strlen(file_basename);
	dest_path_len = (uint8_t)strlen(dest_path);
	skb_reset(skb);
	p = skb_put(skb, 3);
	*p++ = EGETTY_PUSH_START;
	*p++ = file_len;
	*p++ = dest_path_len;
	
	p = skb_put(skb, 8);
	*p++ = (total_file_size >> 56) & 0xFF;
	*p++ = (total_file_size >> 48) & 0xFF;
	*p++ = (total_file_size >> 40) & 0xFF;
	*p++ = (total_file_size >> 32) & 0xFF;
	*p++ = (total_file_size >> 24) & 0xFF;
	*p++ = (total_file_size >> 16) & 0xFF;
	*p++ = (total_file_size >> 8) & 0xFF;
	*p++ = (total_file_size & 0xFF);
	
	p = skb_put(skb,20);//SHA1
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	*p++ = 0xFF;*p++ = 0xFF;
	
	p = skb_put(skb,file_len);//file name
	strncpy(p,file_basename,file_len);
	
	p = skb_put(skb,dest_path_len);//dest path
	strncpy(p,dest_path,dest_path_len);
	
	
	ret = send_ucast(s, ifindex,&from, skb);
	if(ret == -1) {
		fprintf(stderr, "sendto failed: %s\n", strerror(errno));
		return -1;
	}
	
	printf("sleeping after seding ucast \n");
	sleep(3);
	
	printf("Starting sending file loop \n");
	clock_gettime(CLOCK_MONOTONIC_RAW,&start_ts);
	
	uint64_t file_offset = 0;
	uint32_t payload_size = 0;
	
	while(file_offset < total_file_size){
		printf("inside loop \n");
		skb_reset(skb);
		p = skb_put(skb, 1);
		//p = skb_put(skb,40);
		*p++ = EGETTY_PUSH_PART;
		p = skb_put(skb, 8);
		*p++ = (file_offset >> 56) & 0xFF;
		*p++ = (file_offset >> 48) & 0xFF;
		*p++ = (file_offset >> 40) & 0xFF;
		*p++ = (file_offset >> 32) & 0xFF;
		*p++ = (file_offset >> 24) & 0xFF;
		*p++ = (file_offset >> 16) & 0xFF;
		*p++ = (file_offset >> 8) & 0xFF;
		*p++ = (file_offset & 0xFF);
		
		payload_size = 1024;
		if (file_offset + payload_size > total_file_size){
			payload_size = total_file_size - file_offset;
		}
		p = skb_put(skb, 4);
		*p++ = (payload_size >> 24) & 0xFF;
		*p++ = (payload_size >> 16) & 0xFF;
		*p++ = (payload_size >> 8) & 0xFF;
		*p++ = (payload_size & 0xFF);
		
		file_offset = file_offset + payload_size;
		
		//The file bytes(payload)
		if (fread(fb_buf, payload_size, 1, fp) != 1){
			printf("Error reading from file! \n");
			return -1;
		}

		p = skb_put(skb,payload_size);
		memcpy(p,fb_buf,payload_size);
		
		ret = send_ucast(s, ifindex,&from, skb);
		if(ret == -1) {
			fprintf(stderr, "sendto failed: %s\n", strerror(errno));
			return -1;
		}
		usleep(50000);
		usleep(50000);
		usleep(50000);
		usleep(50000);
		usleep(50000);
		usleep(50000);
	}
	fclose(fp);
	printf("Done pushing file! \n");
	/*
	struct pollfd fds[1];
	fds[0].fd = conf.s;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	
	
	
	while(1){
		if (conf.debug)
			printf("polling... \n");
		n = poll(fds,1,3000);
		if (conf.debug)
			printf("Got polled by: %d \n",n);
		if (seconds_elapsed_from(&start_ts) > 3){//Time Elapsed
			break;
		}
		
		if (n == 1){
			skb_reset(skb);
			buf = skb_put(skb, 0);
			rec_n = recvfrom(conf.s, buf, skb_tailroom(skb), 0, (struct sockaddr *)&from, &fromlen);
			if(rec_n == -1) {
				fprintf(stderr, "recvfrom() failed. ifconfig up?\n");
				continue;
			}
			skb_put(skb, rec_n);

			if(conf.ucast)
				if(memcmp(conf.dest.sll_addr, from.sll_addr, 6))
					continue;
		
			if(ntohs(from.sll_protocol) == ETH_P_EGETTY) {
				if(conf.debug) printf("Received EGETTY\n");
				p = skb->data;
				if(*p == EGETTY_HELLO) {
						p++;
						printf("Console: %d ", *p);
						for(i=0;i<6;i++)
							printf("%02x%s", from.sll_addr[i], i==5?"":":");
						printf("\n");
					continue;
				}
			}
			
		}else if (n == 0){//Timeout
			break;
		}
		
		
	}*/
	console_hup(conf.s, conf.ifindex);
	//tcsetattr(0, TCSANOW, &conf.term);
	
	//printf("Exiting devices \n");
	return 0;
}

void usage_exit()
{
	printf("econsole [(-i <iface> (-m <mac))] ping - ping to remote console \n");
	printf("econsole [(-i <iface> (-m <mac))] shell - get remote shell \n");
	printf("econsole [(-i <iface>)] devices - get devices available in the interface \n");
	exit(0);
}

int main(int argc, char **argv)
{

	char *device = "eth0", *ps;
	uint8_t *buf, *p;
	int i, err=0;
	unsigned int len;
	struct sk_buff *skb;

	conf.ifindex=-1;
	conf.debug = 0;
	conf.devices = 0;
	conf.shell = 0;
	
	char iface[128];
	char mac[128];
	char push_file[1024],push_dest_path[1024];
	int use_mac,use_iface;
	int do_ping,do_push,do_devices,do_shell;
	
	use_mac = 0;
	use_iface = 0;
	do_ping = 0;
	do_push = 0;
	do_devices = 0;
	do_shell = 0;
	
	/*if(jelopt(argv, 'h', "help", NULL, &err)) {
		printf("econsole [DEV] [DESTMAC] [(scan|debug)]\n"); 
		printf("econsole [DEV] [DESTMAC] [(devices)] - list available consoles\n");
		printf("econsole [DEV] [DESTMAC] [(shell)] - get shell\n");
		printf("econsole [DEV] [DESTMAC] [(push <src-file> <dest-path>)] - push a file to remote\n");
		printf("econsole [(-i <iface>)|(-m <mac)] ping - ping to remote console \n");
		printf("ex. 'sudo econsole eth0 shell' \n");
		exit(0);
	}*/
	//argc = jelopt_final(argv, &err);
	//if(err) {
	//	printf("Syntax error in arguments.\n");
	//	exit(2);
	//}
	argc--;
	argv++;
	

	while(argc > 0){
		printf("argv: %s \n",argv[0]);
		if (strcmp(argv[0],"-i") == 0){
			
			argc--;
			argv++;
			if (argc == 0){
				usage_exit();
			}
			
			strncpy(iface,argv[0],128);
			use_iface = 1;
			argc--;
			argv++;
		}else if (strcmp(argv[0],"-m") == 0){
			argc--;
			argv++;
			if (argc == 0){
				usage_exit();
			}
			strncpy(mac,argv[0],128);
			use_mac = 1;
			argc--;
			argv++;
		}else if (strcmp(argv[0],"devices") == 0){
			do_devices = 1;
			argc--;
			argv++;
		}else if (strcmp(argv[0],"shell") == 0){
			do_shell = 1;
			argc--;
			argv++;
		}else if (strcmp(argv[0],"push") == 0){
			argc--;
			argv++;
			if (argc < 2){
				usage_exit();
			}
			do_push = 1;
			strncpy(push_file,argv[0],1024);
			argc--;
			argv++;
			strncpy(push_dest_path,argv[0],1024);
			argc--;
			argv++;
			printf("push cmd \n");
			
		}
		
		else{
			usage_exit();
		}	
	}
	
	if (!use_iface){
		printf("Must supply interface \n");
		usage_exit();
	}
	if ((do_devices + do_ping + do_shell + do_push) != 1){
		printf("Must select only 1 command \n");
		usage_exit();
	}
	
	conf.devsocket = devsocket();
	printf("Using network interface: %s \n\n",iface);
	while(set_flag(iface, (IFF_UP | IFF_RUNNING))) {
		printf("Waiting for interface [%s] to be available \n",iface);
		sleep(1);
	}

	
	//if(iface){
		conf.ifindex = if_nametoindex(iface);
		if(!conf.ifindex)
		{
			fprintf(stderr, "no such device %s\n", iface);
			exit(1);
		}
	//}

	conf.s = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_EGETTY));
	if(conf.s == -1)
	{
		fprintf(stderr, "socket(): %s\n", strerror(errno));
		exit(1);
	}


	if(conf.ifindex >= 0)
	{
		struct sockaddr_ll addr;
		memset(&addr, 0, sizeof(addr));
		
		addr.sll_family = AF_PACKET;
		addr.sll_protocol = htons(ETH_P_EGETTY);
		addr.sll_ifindex = conf.ifindex;
		
		if(bind(conf.s, (const struct sockaddr *)&addr, sizeof(addr)))
		{
			fprintf(stderr, "bind failed: %s\n", strerror(errno));
			exit(1);
		}
	}
	
	skb = alloc_skb(1500);
	if (do_devices){
		console_devices(conf.s,conf.ifindex,skb,NULL);
	}
	
	if (do_shell){
		terminal_settings();
		signals_init();
		winch_handler(0);
		fprintf(stderr, "Use CTRL-] to close connection.\n");
		console_shell(conf.s,conf.ifindex,skb);
	}
	
	if (do_push){
		printf("do push for file: %s 'into' '%s'\n",push_file,push_dest_path);
		do_push_func(conf.s,conf.ifindex,skb,push_file,push_dest_path);
	}
	
	/*
	

	while(--argc > 0) {
		if(strcmp(argv[argc], "scan")==0) {
			printf("Scanning for econsoles\n");
			conf.scan = 1;
			continue;
		}
		
		if(strcmp(argv[argc], "devices")==0) {
			printf("egetty devices:\n");
			conf.devices = 1;
			continue;
		}
		
		if (strcmp(argv[argc],"shell") == 0){
			conf.shell = 1;
			continue;
		}
		
		if(strcmp(argv[argc], "debug")==0) {
			printf("Debug mode\n");
			conf.debug++;
			continue;
		}
		
		if (strcmp(argv[argc], "push") == 0){
			printf("pushing .. \n");
			conf.push = 1;
			continue;
		}
		
		if( (strlen(argv[argc]) < 3) && isdigit(*argv[argc])) {
			conf.console = atoi(argv[argc]);
			continue;
		}
		if(strchr(argv[argc], ':' )) {
			unsigned int a;
			ps = argv[argc];
			for(i=0;i<6;i++) {
				sscanf(ps, "%x", &a);
				conf.dest.sll_addr[i] = a;
				ps = strchr(ps, ':');
				if(!ps) break;
				ps++;
			}
			conf.ucast = 1;
			continue;
		} else {
			device = argv[argc];
		}
	}
	
	conf.devsocket = devsocket();
	
	while(set_flag(device, (IFF_UP | IFF_RUNNING))) {
		printf("Waiting for interface [%s] to be available \n",device);
		sleep(1);
	}
	
	if(device)
	{
		conf.ifindex = if_nametoindex(device);
		if(!conf.ifindex)
		{
			fprintf(stderr, "no such device %s\n", device);
			exit(1);
		}
	}

	conf.s = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_EGETTY));
	if(conf.s == -1)
	{
		fprintf(stderr, "socket(): %s\n", strerror(errno));
		exit(1);
	}


	if(conf.ifindex >= 0)
	{
		struct sockaddr_ll addr;
		memset(&addr, 0, sizeof(addr));
		
		addr.sll_family = AF_PACKET;
		addr.sll_protocol = htons(ETH_P_EGETTY);
		addr.sll_ifindex = conf.ifindex;
		
		if(bind(conf.s, (const struct sockaddr *)&addr, sizeof(addr)))
		{
			fprintf(stderr, "bind failed: %s\n", strerror(errno));
			exit(1);
		}
	}

	if(conf.shell == 1) {
		terminal_settings();
		signals_init();
		winch_handler(0);
		fprintf(stderr, "Use CTRL-] to close connection.\n");
	}

	skb = alloc_skb(1500);

	if(conf.scan){
		console_scan(conf.s, conf.ifindex, skb);
	}else if (conf.devices){
		console_devices(conf.s,conf.ifindex,skb);
	}else if (conf.push){
		//push file
	}
	else{
		console_shell(conf.s,conf.ifindex,skb);
	}
	
	exit(0);
	* */
	
	return 0;
}
