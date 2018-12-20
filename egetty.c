
/*
 * File: egetty.c
 * Implements: ethernet getty
 *
 * Copyright: Jens L��s, 2011
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <sys/types.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <unistd.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if_arp.h>
#include <stdio.h>
#include <sys/stat.h>
#include <ctype.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <time.h>

#include <net/if.h>

#include "egetty.h"

#include "skbuff.h"
static char **envp;

struct {
	int console;
	char *device;
	int kmsg;
	int waitif;
	int debug;
	struct sockaddr_ll client;
	int devsocket;
} conf;

char *indextoname(unsigned int ifindex)
{
	static char ifname[IF_NAMESIZE+1];
	
	if(if_indextoname(ifindex, ifname))
		return ifname;
	return "ENXIO";
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

/* Check interface flag. */
static int check_flag(char *ifname, short flag)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	
	strcpy(ifr.ifr_name, ifname);
	
	if (ioctl(conf.devsocket, SIOCGIFFLAGS, &ifr) < 0) {
		return -1;
	}
	return (ifr.ifr_flags & flag) != flag;
}

int putfd(int fd, char *s)
{
	if(s)
		write(fd, s, strlen(s));
	return 0;
}

pid_t logcat(int s, int ifindex, struct sk_buff *skb)
{
	pid_t pid;
	int amaster, tty, rc=0;
	char name[256];
    size_t sz;
	int rc1 = -1;
    char buf [16392];
    uint8_t *p;
    int count;
    count=0;
    pid=fork();
    skb_reset(skb);
	sz = 16392;
    skb=alloc_skb(17000);  
    buf[16392]='\0';
    if(pid==0)
    {
        while(1)
        {
            rc1 = klogctl(3, buf, sz);
            while(count<=16392)
            {
                p = skb_push(skb, 9);
                *p++ = buf[count];
	            *p++ = buf[count+1];
	            *p++ = buf[count+2];
	            *p++ = buf[count+3];
                *p++ = buf[count+4];
	            *p++ = buf[count+5];
	            *p++ = buf[count+6];
	            *p++ = buf[count+7];
                *p = '\0';   
                console_ucast(s,ifindex,skb);
                count+=8;
                skb_reset(skb);
            }   
   
        skb_reset(skb);
        count=0;
        sleep(3);
        }
        exit(1);

    }
    return pid;
}

pid_t login(int *fd)
{
	pid_t pid;
	int amaster, tty, rc=0;
	char name[256];

	pid = forkpty(&amaster, name,
		      NULL, NULL);
	if(pid == 0) {
		/* child */
		if(conf.kmsg) {
			if ((rc = ioctl(0, TIOCCONS, 0))) {
				if(conf.debug) {
					putfd(1, "TIOCCONS: ");
					putfd(1, strerror(errno));
				}
				if (errno == EBUSY) {
					tty = open("/dev/tty0", O_WRONLY);
					if (tty >= 0) {
						if ((rc=ioctl(tty, TIOCCONS, 0))==0) {
							rc=ioctl(0, TIOCCONS, 0);
							if(conf.debug && rc) {
								putfd(1, "TIOCCONS: ");
								putfd(1, strerror(errno));
							}
						}
						close(tty);
					} else
						rc = -1;
				}
			}
			if(conf.debug) {
				if(rc)
					putfd(1, "failed to redirect console\n");
				else
					putfd(1, "redirected console\n");
			}
		}
		
		if ( access("/bin/login",F_OK) != -1){
			//login exists
			char *argv[]={"/bin/login", "--", 0, 0};
			(void) execve( argv[0], argv, envp );
			printf("execve failed\n");
			exit(1);
		}else if (access("/system/bin/sh",F_OK) != -1){
			//We are in Android Linux
			char *argv[]={"/system/bin/sh", "--", 0, 0};
			(void) execve( argv[0], argv, envp );
			printf("execve failed\n");
			exit(1);
		}
	}
	if(pid == -1) return -1;
	*fd = amaster;

	return pid;
}

int console_ucast(int s, int ifindex, struct sk_buff *skb)
{
	struct sockaddr_ll dest;
	socklen_t destlen = sizeof(dest);

	memset(&dest, 0, sizeof(dest));

	dest.sll_family = AF_PACKET;
	dest.sll_halen = 6;
	dest.sll_protocol = htons(ETH_P_EGETTY);
	dest.sll_ifindex = ifindex;
	memcpy(dest.sll_addr, conf.client.sll_addr, 6);
	
	return sendto(s, skb->data, skb->len, 0, (const struct sockaddr *)&dest, destlen);
}

int send_bcast(int s, int ifindex, struct sk_buff *skb)
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

int console_put(int s, int ifindex, struct sk_buff *skb)
{
	int rc;
	uint8_t *p;

	p = skb_push(skb, 4);
	*p++ = EGETTY_OUT;
	*p++ = conf.console;
	*p++ = skb->len >> 8;
	*p = skb->len & 0xff;

	rc = console_ucast(s, ifindex, skb);
	if(rc == -1) {
		printf("sendto failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int console_hello(int s, int ifindex, struct sk_buff *skb)
{
	int rc;
	uint8_t *p;

	p = skb_push(skb, 4);
	*p++ = EGETTY_HELLO;
	*p++ = conf.console;
	*p++ = skb->len >> 8;
	*p = skb->len & 0xff;

	rc = send_bcast(s, ifindex, skb);
	if(rc == -1) {
		printf("sendto failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static long get_filesize(const char* file, uint64_t* file_size)
{
	FILE* fp = fopen(file, "r");
	if (fp == NULL){
		return -1;
	}
	fseek(fp, 0 , SEEK_END);
	long fileSize = ftell(fp);
	fclose(fp);
	
	*file_size = fileSize;
	return fileSize;
}

int send_to_econsole(int s, int ifindex, struct sk_buff *skb)
{
	struct sockaddr_ll dest;
	socklen_t destlen = sizeof(dest);

	memset(&dest, 0, sizeof(dest));

	dest.sll_family = AF_PACKET;
	dest.sll_halen = 6;
	dest.sll_protocol = htons(ETH_P_EGETTY);
	dest.sll_ifindex = ifindex;
	memcpy(dest.sll_addr, conf.client.sll_addr, 6);
	
	return sendto(s, skb->data, skb->len, 0, (const struct sockaddr *)&dest, destlen);
}

void dump_buf(char *buf, int len)
{
	printf("buf: %s \n",buf);
}


int is_ends_with_char(const char *str,int len,char suffix)
{
	if (str[len-1] == suffix){
		return 1;
	}
	
	return 0;
}

int is_regular_file(const char *path)
{
	int ret = 0;
    struct stat path_stat;
    stat(path, &path_stat);
    ret = S_ISREG(path_stat.st_mode);
    
    
    return ret;
}

int is_path_existing_dir(const char* path)
{
   // const char* folderr;
    //folderr = "C:\\Users\\SaMaN\\Desktop\\Ppln";
   // folderr = "/tmp";
    struct stat sb;

    if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        printf("DIR EXISTS YES\n");
        return 1;
    }
    printf("DIR DOES NOT EXIST \n");
    return 0;

}

int main(int argc, char **argv, char **arge)
{
	int ret;
	int s;
	struct sockaddr_ll from;
	socklen_t fromlen = sizeof(from);
	int ifindex=-1;
	uint8_t *buf, *p;
	ssize_t n;
	uint32_t i;
	unsigned int len;
	//int count=1;
	int timeout = -1;
	int loginfd = -1;
	pid_t pid=-1;
	struct sk_buff *skb;
	int k = 0;
	FILE *fd;
	FILE *pull_fd;
	char fd_buf[1024];
	char pushed_file_path[256];
	uint64_t pushed_file_total_size = 0;
	
	char streambuf[65536];
	char pull_buf[4096];
	envp = arge;
	conf.debug = 0;
	conf.device = "eth0";
	conf.devsocket = -1;

	while(--argc > 0) {
		if(strcmp(argv[argc], "debug")==0) {
			printf("Debug mode\n");
			conf.debug = 1;
			continue;
		}
		if(strcmp(argv[argc], "console")==0) {
			conf.kmsg = 1;
			continue;
		}
		if(strcmp(argv[argc], "waitif")==0) {
			conf.waitif = 1;
			continue;
		}
		if( (strlen(argv[argc]) < 3) && isdigit(*argv[argc])) {
			conf.console = atoi(argv[argc]);
			continue;
		}
		conf.device = argv[argc];
	}

	conf.devsocket = devsocket();
	
	if(conf.waitif) {
		/* wait for interface to become available */
		while(check_flag(conf.device, (IFF_UP | IFF_RUNNING))) {
			sleep(1);
		}
	} else {
		/* active interface */
		while(set_flag(conf.device, (IFF_UP | IFF_RUNNING))) {
			sleep(1);
		}
	}
	
	memset(conf.client.sll_addr, 255, 6);
	
	s = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_EGETTY));
	if(s == -1)
	{
		fprintf(stderr, "socket(): %s\n", strerror(errno));
		exit(1);
	}
	
	if(conf.device)
	{
		ifindex = if_nametoindex(conf.device);
		if(!ifindex)
		{
			fprintf(stderr, "Not an interface\n");
			exit(1);
		}
	}
	
	
	if(ifindex >= 0)
	{
		struct sockaddr_ll addr;
		memset(&addr, 0, sizeof(addr));
		
		addr.sll_family = AF_PACKET;
		addr.sll_protocol = htons(ETH_P_EGETTY);
		addr.sll_ifindex = ifindex;
		
		if(bind(s, (const struct sockaddr *)&addr, sizeof(addr)))
		{
			fprintf(stderr, "bind() to interface failed\n");
			exit(1);
		}
	}
	 printf("im here \n");
	skb = alloc_skb(1500);

	skb_reset(skb);
	skb_reserve(skb, 4);
	console_hello(s, ifindex, skb);
	while(1)
	{
		struct pollfd fds[2];

		if(pid) {
			int status;
			if(waitpid(-1, &status, WNOHANG)>0) {
				pid = -1;
				close(loginfd);
			}
		}
		if(pid == -1) {
			pid = login(&loginfd);
			if(pid == -1)
				exit(1);
			if(conf.debug) {
				printf("child pid = %d\n", pid);
				printf("loginfd = %d\n", loginfd);
			}
		}
		
		fds[0].fd = s;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		
		fds[1].fd = loginfd;
		fds[1].events = POLLIN;
		fds[1].revents = 0;

		n = poll(fds, 2, timeout);
		if(n == 0) {
			printf("timeout\n");
			exit(1);
		}
	
		if(fds[1].revents & POLLIN) {
			if(conf.debug) printf("POLLIN child\n");
			skb_reset(skb);
			skb_reserve(skb, 4);
			buf = skb_put(skb, 0);
			n = read(loginfd, buf, skb_tailroom(skb));
			if(n == -1) {
				fprintf(stderr, "read() failed\n");
				exit(1);
			}
			
			buf[n] = 0;
			if(conf.debug)
				printf("child: %d bytes\n", n);
			skb_put(skb, n);
			console_put(s, ifindex, skb);
		}
		if(fds[0].revents) {
			
			
			skb_reset(skb);
			buf = skb_put(skb, 0);
			n = recvfrom(s, buf, skb_tailroom(skb), 0, (struct sockaddr *)&from, &fromlen);
			if(n == -1) {
				fprintf(stderr, "recvfrom() failed. ifconfig up?\n");
				exit(1);
			}

			skb_put(skb, n);
			if(conf.debug) printf("received packet %d bytes\n", skb->len);
			
			if(ntohs(from.sll_protocol) == ETH_P_EGETTY) {
				
				if(conf.debug)
					printf("Received EGETTY\n");
				
				p = skb->data;
				if(*p == EGETTY_HUP) {
					if(pid != -1) kill(pid, 9);
					continue;
				}else if(*p == EGETTY_SCAN) {
					skb_reset(skb);
					skb_reserve(skb, 4);
					console_hello(s, ifindex, skb);
					continue;
				}

                  else if(*p == 120)
               {
                   printf("receiving log file\n");
                   skb_reset(skb);
				   skb_reserve(skb, 4);    
                   logcat(s,ifindex,skb);
                   continue;

                }
                  else if (*p == EGETTY_PUSH_START){
					p++;
					printf("Got EGETTY_PUSH_START push start \n");
					int len1 = *p++;
					int len2 = *p++;
					pushed_file_total_size = 0;
					
					pushed_file_total_size = pushed_file_total_size | ( (*p++) << 56);
					pushed_file_total_size = pushed_file_total_size | ( (*p++) << 48);
					pushed_file_total_size = pushed_file_total_size | ( (*p++) << 40);
					pushed_file_total_size = pushed_file_total_size | ( (*p++) << 32);
					pushed_file_total_size = pushed_file_total_size | ( (*p++) << 24);
					pushed_file_total_size = pushed_file_total_size | ( (*p++) << 16);
					pushed_file_total_size = pushed_file_total_size | ( (*p++) << 8);
					pushed_file_total_size = pushed_file_total_size |   (*p++);
					
					
					
					char sha1[20];
					for (k = 0; k<20; k++){
						sha1[k] = (*p++);
					}
					
					char filename[128];
					memset(filename,0,128 * sizeof(char));
					for (k = 0; k < len1; k++){
						filename[k] = (*p++);
					}
					
					char dest_path[128];
					memset(dest_path,0,128 *sizeof(char));
					for (k = 0; k < len2; k++){
						dest_path[k] = (*p++);
					}
					
					printf("len1: %d, len2: %d total_size: %lld filename: %s info: [%s]\n",len1,len2,pushed_file_total_size,filename,dest_path);
					
					memset(pushed_file_path,0,256 * sizeof(char));
					if (is_path_existing_dir(dest_path)){
						//Here we will create/override the file: dest_path/filename
						
						memcpy(pushed_file_path,dest_path,len2);
						
						if (!is_ends_with_char(dest_path,len2,'/')){
							pushed_file_path[len2] = '/';
							memcpy(pushed_file_path + len2 + 1,filename,len1);
						}else{
							memcpy(pushed_file_path + len2,filename,len1);
						}
						
						printf("Will write new file into: %s \n",pushed_file_path);
						
						
					}else if (is_regular_file(dest_path)){
						//Here we just write into dest_path without using filename at all
						memcpy(pushed_file_path,dest_path,len2);
						printf("RegFile Will write new file into: %s \n",pushed_file_path);
					}
					
					//else{
					//	printf("Error no path or file in: %s \n",dest_path);
					//	continue;
					//}
					
					fd = fopen(pushed_file_path,"wb+");
					if (fd == NULL){
						printf("Could not open file! \n");
						continue;
					}
					//if (setvbuf(fd,streambuf,_IOFBF,65536) != 0){
					//	printf("setvbuf() error \n");
						//continue;
					//}

					
					
					
					//TODO: Check path if it exists. If its a directory, or file
					
				//	fd = fopen(
					continue;
				}else if (*p == EGETTY_PUSH_PART){
					p++;
					printf("Got EGETTY_PUSH_PART \n");
					uint64_t file_offset = 0;
					uint32_t payload_size = 0;
					
					file_offset = file_offset | ( (*p++) << 56);
					file_offset = file_offset | ( (*p++) << 48);
					file_offset = file_offset | ( (*p++) << 40);
					file_offset = file_offset | ( (*p++) << 32);
					file_offset = file_offset | ( (*p++) << 24);
					file_offset = file_offset | ( (*p++) << 16);
					file_offset = file_offset | ( (*p++) << 8);
					file_offset = file_offset |   (*p++);
					
					payload_size = payload_size | ( (*p++) << 24);
					payload_size = payload_size | ( (*p++) << 16);
					payload_size = payload_size | ( (*p++) << 8);
					payload_size = payload_size |   (*p++);
					
					printf("File offset: %lld, payload size: %d \n",file_offset,payload_size);
					
					for (k = 0; k < payload_size; k++){
						fd_buf[k] = (*p++);
					}
					ret = fwrite(fd_buf,payload_size,1,fd);
					printf("write result: %d \n",ret);
					fflush(fd);
					
					if (ret == 0){
						printf("Exiting, as fwrite failed! \n");
						exit(0);
					//	ferror(ret);
					}
					
					if (payload_size + file_offset == pushed_file_total_size){
						printf("File written! \n");
						fclose(fd);
					}
					
					
					continue;
					
				}else if (*p == EGETTY_PULL_START_REQUEST){
					p++;
					printf("Got EGETTY_PULL_START_REQUEST \n");
					uint32_t len = 0;
					uint64_t file_size = 0;
					char* file_path;
					
					len = len | ( (*p++) << 24);
					len = len | ( (*p++) << 16);
					len = len | ( (*p++) << 8);
					len = len |   (*p++);

					for (i=0; i<len; i++){
						streambuf[i] = (*p++);
					}
					streambuf[i] = NULL;
					file_path = streambuf;
					if (get_filesize(file_path, &file_size) < 0){
						printf("could not get file size, file not accessible\n");
						skb_reset(skb);
						p = skb_put(skb, 1);
						*p++ = EGETTY_ERROR;
					}else{
						pull_fd = fopen(file_path, "r");
						skb_reset(skb);
						p = skb_put(skb, 1);
						*p++ = EGETTY_PULL_START_RESPONSE;
					
						p = skb_put(skb, 8);
						*p++ = (file_size >> 56) & 0xFF;
						*p++ = (file_size >> 48) & 0xFF;
						*p++ = (file_size >> 40) & 0xFF;
						*p++ = (file_size >> 32) & 0xFF;
						*p++ = (file_size >> 24) & 0xFF;
						*p++ = (file_size >> 16) & 0xFF;
						*p++ = (file_size >> 8) & 0xFF;
						*p++ = (file_size & 0xFF);
					}
					
					send_to_econsole(s, ifindex, skb);
					continue;
				}else if (*p == EGETTY_PULL_PART_REQUEST){
					p++;
					printf("Got EGETTY_PULL_PART_REQUEST \n");
					uint64_t file_offset = 0;
					uint32_t payload_size = 0;
					
					file_offset = file_offset | ( (*p++) << 56);
					file_offset = file_offset | ( (*p++) << 48);
					file_offset = file_offset | ( (*p++) << 40);
					file_offset = file_offset | ( (*p++) << 32);
					file_offset = file_offset | ( (*p++) << 24);
					file_offset = file_offset | ( (*p++) << 16);
					file_offset = file_offset | ( (*p++) << 8);
					file_offset = file_offset |   (*p++);
					
					payload_size = payload_size | ( (*p++) << 24);
					payload_size = payload_size | ( (*p++) << 16);
					payload_size = payload_size | ( (*p++) << 8);
					payload_size = payload_size |   (*p++);

					fseek(pull_fd, file_offset, SEEK_SET);
					fread(pull_buf, payload_size, 1, pull_fd);
					
					skb_reset(skb);
					p = skb_put(skb, 1);
					*p++ = EGETTY_PULL_PART_RESPONSE;
					
					p = skb_put(skb, 4);
					*p++ = (payload_size >> 24) & 0xFF;
					*p++ = (payload_size >> 16) & 0xFF;
					*p++ = (payload_size >> 8) & 0xFF;
					*p++ = (payload_size & 0xFF);

					p = skb_put(skb, payload_size);
					memcpy(p, pull_buf, payload_size);
					send_to_econsole(s, ifindex, skb);
					continue;
				}else if(*p == EGETTY_WINCH) {
					p++;
					if(*p != conf.console) {
						if(conf.debug)
							printf("Wrong console %d not %d\n", *p, conf.console);
						continue;
					}
					p++;
					{
						struct winsize winp;
						winp.ws_row = *p++;
						winp.ws_col = *p++;
						winp.ws_xpixel = 0;
						winp.ws_ypixel = 0;
						ioctl(loginfd, TIOCSWINSZ, &winp);
						if(conf.debug)
							printf("WINCH to %d, %d\n", winp.ws_row, winp.ws_col);
					}
					continue;
				}
				
				else if(*p != EGETTY_IN) {
					if(conf.debug)
						printf("Not EGETTY_IN: %d\n", *p);
					continue;
				}else{
				p++;
				if(*p != conf.console) {
					if(conf.debug)
						printf("Wrong console %d not %d\n", *p, conf.console);
					continue;
				}
				memcpy(conf.client.sll_addr, from.sll_addr, 6);
				p++;
				len = *p++ << 8;
				len += *p;
				if(len > n) {
					printf("Length field too long: %d\n", len);
					continue;
				}
				skb_trim(skb, len);
				skb_pull(skb, 4);
				if(conf.debug) {
					printf("Sent %d bytes to child\n", skb->len);
					dump_buf(skb->data,skb->len);
				}
				write(loginfd, skb->data, skb->len);
				continue;
			}
			}
		}
		
	}
  exit(0);
}


