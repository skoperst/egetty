#ifndef EGETTY_H
#define EGETTY_H

#define ETH_P_EGETTY 0x6811

enum { 
	EGETTY_SCAN=0, 
	EGETTY_KMSG, 
	EGETTY_HUP, 
	EGETTY_HELLO, 
	EGETTY_IN, 
	EGETTY_OUT, 
	EGETTY_WINCH,
	EGETTY_PUSH_START,//[EGETTY_PUSH_START-1 byte][strlen file-1 byte][strlen destination-1 byte][file-size - 8 bytes][SHA1 of file - 20 bytes]['file']['destination']
	EGETTY_PUSH_PART,//[EGETTY_PUSH_PART- 1 byte][file_offset-8 bytes][payload_size - 4 bytes][payload]
	EGETTY_PULL_START_REQUEST,//[EGETTY_PULL_START_REQUEST-1 byte][path of file to pull len - 4 bytes][path of file to pull]
	EGETTY_PULL_PART_REQUEST=10,
	EGETTY_PULL_START_RESPONSE,
	EGETTY_PULL_PART_RESPONSE,
	EGETTY_LOGCAT,
	EGETTY_ERROR,
	
	 };

/*
 Format of packet:
 uint8_t type;
 uint8_t console_no;
 uint8_t len_high;
 uint8_t len_low;

 uint8_t data[];

 */


typedef struct egetty_server_struct{
	
}egetty_server_t;
#endif


