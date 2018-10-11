/*--------------------------------------------------------
 *  Copyright(C) 2018 EASTCOM-BUPT Inc.
 *
 *  Author      : even li
 *  Description : even li at ebupt.com
 *  History     : 2015-04-12 Created
 *
 *   Module Name:
 *   rt2860v2-detect-user
 *
 *   Abstract:
 *   receive detect data from kernel
 *
 *--------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>

#define NETLINK_TEST 17
#define MSG_LEN 512

struct msg_to_kernel
{
    struct nlmsghdr hdr;
    char data[MSG_LEN];
};

struct u_packet_info
{
    struct nlmsghdr hdr;
    unsigned char msg[MSG_LEN];
};

typedef enum APGUY_TYPE
{
	NULL_TYPE,
	LISTEN_TYPE,
	MAXCLIENT_TYPE,
	STATE_TYPE
}apguy_type;

static int netlink_usage(void)
{
	fprintf(stderr, "Usage: (null) [options]\n"
		"Options:\n"
		" -l :		                  Listen and monitor WIFI client events\n"
		" -d <mac addr>:		        Delete a client by it's MAC\n"
		" -m <mac client count>:		set the max client count, it should be less than 211\n"
		" -g :		                  Get the station information\n"
		"\n");

	return 1;
}

//get sta status e.x mac rssi 
void get_wifi_state(void){
	char *data = "g";
    struct sockaddr_nl local;
    struct sockaddr_nl kpeer;
    int skfd, ret, kpeerlen = sizeof(struct sockaddr_nl);
    struct nlmsghdr *message;
    struct u_packet_info info;
    char *retval;
    int len=0;

	apguy_type state = NULL_TYPE;

	message = (struct nlmsghdr *)malloc(1);

    skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd < 0){
        printf("can not create a netlink socket\n");
        return ;
    }
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    local.nl_groups = 1;
    if(bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0){
        printf("bind() error\n");
        return ;
    }
    memset(&kpeer, 0, sizeof(kpeer));
    kpeer.nl_family = AF_NETLINK;
    kpeer.nl_pid = 0;
    kpeer.nl_groups = 1;

    memset(message, '\0', sizeof(struct nlmsghdr));
    message->nlmsg_len = NLMSG_SPACE(strlen(data));
    message->nlmsg_flags = 0;
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0;
    message->nlmsg_pid = local.nl_pid;

    retval = memcpy(NLMSG_DATA(message), data, strlen(data));

    ret = sendto(skfd, message, message->nlmsg_len, 0,(struct sockaddr *)&kpeer, sizeof(kpeer));
    if(!ret){
        perror("send pid:");
        exit(-1);
    }

    while(recvfrom(skfd, &info, sizeof(struct u_packet_info),0, (struct sockaddr*)&kpeer, &kpeerlen)){
    	len=strlen(info.msg);
    	//printHex(info.msg, len);
    	switch(info.msg[0]){
    		case 4:
    			//data frame
    			printf("%02x:%02x:%02x:%02x:%02x:%02x %d %d %d %d %dM %d %d\n", info.msg[2], info.msg[3], info.msg[4], info.msg[5], info.msg[6], info.msg[7], info.msg[8], info.msg[9], info.msg[10], info.msg[11] ,info.msg[12], info.msg[13], info.msg[13]);
    			break;
    			
    		case 9:
    			close(skfd);
    			return;
    			
    		default:
                printf("this is not stat status, msg is %s\n", info.msg);
                close(skfd);
                return;
    			break;
    	}
    	fflush(stdout);
    }

    close(skfd);
}

void listen_wifi_events(void){
	struct sockaddr_nl local;
    struct sockaddr_nl kpeer;
    int skfd, ret, kpeerlen = sizeof(struct sockaddr_nl);
    struct u_packet_info info;
    int len=0;

	
	skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
	if(skfd < 0){
		printf("can not create a netlink socket\n");
		return -1;
	}
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 1;
	if(bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0){
		printf("bind() error\n");
		return -1;
	}
	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 1;
	
	while(recvfrom(skfd, &info, sizeof(struct u_packet_info),0, (struct sockaddr*)&kpeer, &kpeerlen)){
    	len=strlen(info.msg);
    	//printHex(info.msg, len);
    	switch(info.msg[0]){
    		case 1:
    			//data frame
    			printf("DATA====> (-001) [%02x:%02x:%02x:%02x:%02x:%02x] RSSI:{-%d,-%d,-99} SNR:%d, %d, %d\n", info.msg[2], info.msg[3], info.msg[4], info.msg[5], info.msg[6], info.msg[7], info.msg[8], info.msg[9], info.msg[11], info.msg[12], info.msg[13]);
    			break;
    			
    		case 2:
    			//mgmgt frame
    			switch(info.msg[1])
    			{
    					case 0:
    						printf("ASSOC===> (0002) [%02x:%02x:%02x:%02x:%02x:%02x] RSSI:{-%d,-%d,-99} SNR:%d, %d, %d\n", info.msg[2], info.msg[3], info.msg[4], info.msg[5], info.msg[6], info.msg[7], info.msg[8], info.msg[9], info.msg[11], info.msg[12], info.msg[13]);
    						break;
    					case 2:
    						printf("REASSOC===> (-001) [%02x:%02x:%02x:%02x:%02x:%02x] RSSI:{-%d,-%d,-99} SNR:%d, %d, %d\n", info.msg[2], info.msg[3], info.msg[4], info.msg[5], info.msg[6], info.msg[7], info.msg[8], info.msg[9], info.msg[11], info.msg[12], info.msg[13]);
    						break;
    					case 4:
    						printf("PROBE===> (-001) [%02x:%02x:%02x:%02x:%02x:%02x] RSSI:{-%d,-%d,-99} SNR:%d, %d, %d\n", info.msg[2], info.msg[3], info.msg[4], info.msg[5], info.msg[6], info.msg[7], info.msg[8], info.msg[9], info.msg[11], info.msg[12], info.msg[13]);
    						break;
    					case 8:
    						printf("BEACON==> (-001) [%02x:%02x:%02x:%02x:%02x:%02x] RSSI:{-%d,-%d,-99} SNR:%d, %d, %d\n", info.msg[2], info.msg[3], info.msg[4], info.msg[5], info.msg[6], info.msg[7], info.msg[8], info.msg[9], info.msg[11], info.msg[12], info.msg[13]);
    						break;
    					case 10:
    						printf("DISASSOC=> (0002) [%02x:%02x:%02x:%02x:%02x:%02x] RSSI:{-%d,-%d,-99} SNR:%d, %d, %d\n", info.msg[2], info.msg[3], info.msg[4], info.msg[5], info.msg[6], info.msg[7], info.msg[8], info.msg[9], info.msg[11], info.msg[12], info.msg[13]);
    						break;
    					default:
    						break;
    			}
    			break;
    	
    		case 3:
    			//control frame
    			//printf("CONTROL=> (-001) [%02x:%02x:%02x:%02x:%02x:%02x] RSSI:{-%d,-%d,-99} SNR:%d, %d, %d\n", info.msg[2], info.msg[3], info.msg[4], info.msg[5], info.msg[6], info.msg[7], info.msg[8], info.msg[9], info.msg[11], info.msg[12], info.msg[13]);
    			break;
    		
    		default:
    			break;
    	}
    	fflush(stdout);
    }
	close(skfd);
}

void set_wifi_maxclients(char max){
	//todo
}

int main(int argc, char* argv[]) {
	apguy_type state = NULL_TYPE;

	if(argv[1] == NULL){
        return netlink_usage();
    }
	
	if(strcmp(argv[1], "-g") == 0){
		state=STATE_TYPE;
	}
	
	if(strcmp(argv[1], "-l") == 0){
		state=LISTEN_TYPE;
	}
	
	if(strcmp(argv[1], "-m") == 0){
		state=MAXCLIENT_TYPE;
	}
	
	if(state == NULL_TYPE){
		return netlink_usage();
	}
		
	if (state == STATE_TYPE){
		get_wifi_state();
	}
	else if (state == LISTEN_TYPE){
		listen_wifi_events();
	}
	else if (state == MAXCLIENT_TYPE){
		char max=64;
		set_wifi_maxclients(max);
	}else{
		printf("error--------------\n");
	}
    
    return 0;
}

