#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <time.h>
#include <malloc.h>
#include <stdio.h>
#include "winsock2.h"   //need winsock for inet_ntoa and ntohs methods

#define HAVE_REMOTE
#include <pcap.h>   //Winpcap :)

#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap

#define MAXATTACK 100
int requestCount;
int rep_count;
typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

typedef struct arp_hdr
{
	unsigned short hType; //hardware type
	unsigned short pType; //protocol type
	unsigned char hln; // ICMP Error type
	unsigned char pln; // Type sub code
	unsigned short op; //operationn
	unsigned char ar_sha[6];  // Sender MAC
	unsigned char ar_sip[4];  // Sender IP
	unsigned char ar_tha[6];  // Target mac
	unsigned char ar_tip[4];  // Target IP
} ARP_HDR;

static const int ARP_SIZE = sizeof(struct arp_hdr);

typedef struct rep_list{
	unsigned char mac[6];
	int count;
} REPLY;

typedef struct req_list
{
	unsigned char ip[4];
	int count;
} REQUEST;


typedef struct reply_attacker{
	unsigned char amac[6];  // Sender MAC
} REP_ATTACKER;

typedef struct request_attacker{
	unsigned char aip[4];  // Sender IP
} REQ_ATTACKER;

typedef struct reply_attacker_list{
	REP_ATTACKER attacker[50];
	int attackCount;
} REP_ATTACKER_LIST;

typedef struct request_attacker_list{
	REQ_ATTACKER attacker[50];
	int attackCount;
} REQ_ATTACKER_LIST;

REP_ATTACKER_LIST rep_attackerList;
REQ_ATTACKER_LIST req_attackerList;

ETHER_HDR *ethhdr;
ARP_HDR *arpheader;
u_char *data;


time_t req_start_time;//첫번째 request가 들어온 시간
time_t req_end_time; //지정한 개수의 request가 다 들어온
time_t replyStart, replyEnd;
int req_list_count;//req를 요청했던 host들의 카운트를 센다
int req_count; //req를 요청했던 host들의 카운트를 센다
int rep_list_count;//현재 reply list 안에 들어있는 host의 수
int rep_count;

int rep_attack_count;
int req_attack_count;
REQUEST *req_list;
REPLY *rep_list;
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	int i,j, isExist = 0;
	int maxcount = 0;
	int maxindex = 0;

	arpheader = (ARP_HDR*)(pkt_data + sizeof(ETHER_HDR));

	//request인 경우
	if (ntohs(arpheader->op) == 1){
		//기존에 등록된 공격자의 공격인지 검사
		for (i = 0; i < req_attackerList.attackCount; i++){
			if (!memcmp(req_attackerList.attacker[i].aip, arpheader->ar_sip, 4)){
				req_attack_count++;
				if ((req_attack_count % 20) == 0)
				{
					printf("arp request attacker ");
					for (j= 0; j < 4; j++)
						printf("%d.", req_attackerList.attacker[i].aip[j]);
					printf("has attacked \n");
				}
				return;
			}
		}
		//제일 처음 들어온 request 패킷일 경우
		if (req_count == 0)
		{
			req_start_time = time(0);;
			req_count++;
		}
		//제일 마지막(조건의 마지막) request 패킷일 경우
		else if (req_count == MAXATTACK - 1)
		{
			req_end_time = time(0);
			req_count++;
		}
		else//1~49일 경우
			req_count++;

		//중복 검사
		for (i = 0; i < req_list_count; i++)
		{
			if (!memcmp(&req_list[i].ip, &arpheader->ar_sip, 4))
			{
				req_list[i].count++;
				isExist = 1;
				break;
			}
		}
		if (!isExist)//만약 중복이 아니었다면
		{//새로 등록
			memcpy(&req_list[req_list_count].ip, &arpheader->ar_sip, 4);
			req_list[req_list_count].count++;
			req_list_count++;
		}

		//마지막 패킷이 들어왔을 경우 검사
		if (req_count == MAXATTACK)
		{//시간 차이 검사
			if (difftime(req_end_time,req_start_time) < 2)
			{//첫 패킷과 마지막 패킷의 시간 차이가 2초 미만이었다면
				//공격 발생
				for (i = 0; i < req_list_count; i++)
				{//어느 패킷이 제일 많이 들어왔나 검사
					if (maxcount < req_list[i].count)
					{
						maxindex = i;
						maxcount = req_list[i].count;
					}
				}
				printf("호스트 아이피 '");
				for (i = 0; i < 4; i++)
					printf("%d.", req_list[maxindex].ip[i]);
				printf("'로부터 arp request attack이 감지되었습니다\n");
				//request attacker list에다가 추가
				memcpy(req_attackerList.attacker[req_attackerList.attackCount].aip, req_list[maxindex].ip, 4);
				req_attackerList.attackCount++;
			}
			//printf("request 다시 시작\n");
			free(req_list);
			req_list = (REQUEST	*)malloc(sizeof(REQUEST) * 100);
			req_list_count = 0;
			req_start_time = 0;
			req_end_time = 0;
			req_count = 0;
		}
	}
	else{
		//attacker의 공격인지 검사
		for (i = 0; i < rep_attackerList.attackCount; i++){
			if (!memcmp(rep_attackerList.attacker[i].amac, arpheader->ar_sha, 6)){
				rep_attack_count++;
				if ((rep_attack_count % 20)==0)
				{
					printf("arp reply attacker ");
					for (j = 0; j < 6; j++)
						printf("%02X:", rep_attackerList.attacker[i].amac[j]);
					printf("has attacked \n");
				}
				return;
			}
		}
		//제일 처음 들어온 reply의 패킷일 경우
		if (rep_count == 0){
			time(&replyStart);
			//printf("reply start : %d\n", replyStart);
			rep_count++;
		}
		//제일 마지막에 들어온 reply의 패킷일 경우
		else if (rep_count == MAXATTACK - 1){
			time(&replyEnd);
			//printf("reply End : %d\n", replyEnd);
			rep_count++;
		}
		else
			rep_count++;

		//제일 처음에 들어왔을 경우
		for (i = 0; i < rep_list_count; i++)
		{
			//중복이 있으면
			if (!memcmp(rep_list[i].mac, arpheader->ar_sha, 6))
			{
				req_list[i].count++;
				isExist = 1;
				break;
			}
		}
		if (!isExist)//중복이 아니라면 새로 삽입
		{
			memcpy(rep_list[rep_list_count].mac, arpheader->ar_sha, 6);
			rep_list[rep_list_count].count++;
			rep_list_count++;
		}
		if (rep_count == MAXATTACK)
		{
			//우선 시간차이 비교
			if ((replyEnd - replyStart) <= 1)
			{//첫 패킷과 마지막 패킷의 시간 차이가 1보다 작거나 같을 경우 공격이다
				//어느 호스트에서 제일 많은 reply가 왔는지 찾는다
				for (i = 0; i < rep_list_count; i++)
				{
					if (maxcount < rep_list[i].count)
					{
						maxindex = i;
						maxcount = rep_list[i].count;
					}
				}
				printf("호스트 MAC 주소 '");
				for (i = 0; i < 6; i++)
					printf("%02X:", rep_list[maxindex].mac[i]);
				printf("'로부터 arp reply attack이 감지되었습니다\n");
				//reply attacker list에다 추가
				memcpy(rep_attackerList.attacker[rep_attackerList.attackCount].amac, rep_list[maxindex].mac, 6);
				rep_attackerList.attackCount++;
			}
			printf("Reply 다시 시작\n");
			free(rep_list);
			rep_list = (REPLY *)malloc(sizeof(REPLY) * 100);
			rep_list_count = 0;
			replyStart = 0;
			replyEnd = 0;
			rep_count = 0;
		}

	}

}

int main(int argc, char *argv[])
{
	bpf_u_int32 netmask = 0, maskp = 0;        // net address, netmask 정보를 저장한다.
	struct bpf_program fcode;
	u_int i, inum;
	u_char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	char query[100] = "not src host ";
	req_list = (REQUEST *)malloc(sizeof(REQUEST) * 100);
	rep_list = (REPLY *)malloc(sizeof(REPLY) * 100);
	if (argc != 2)
	{
		printf("Usage : final.exe YOUR IP\n");

	}
	strcat(query, argv[1]);
	strcat(query, " and arp");
	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}
	i = 0;
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);

		if (d->description)
		{
			printf(" (%s)\n", d->description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}

	if (i == 0)
	{
		fprintf(stderr, "No interfaces found! Exiting.\n");
		return -1;
	}

	printf("Enter the interface number you would like to capture : ");
	scanf_s("%d", &inum);


	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	if ((fp = pcap_open(d->name,
		100 /*snaplen*/,
		PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
		20 /*read timeout*/,
		NULL /* remote authentication */,
		errbuf)
		) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		return -1;
	}
	if (pcap_lookupnet(d->name, &netmask, &maskp, errbuf))
	{
		printf("pcap_lookupnet Error!\n");
		return -1;
	}

	if (pcap_compile(fp, &fcode, query, 1, netmask) < 0)
	{
		printf("Filter Compiling Error : Syntex Error!\n");
		pcap_close(fp);
		return -1;
	}
	if (pcap_setfilter(fp, &fcode) < 0)
	{
		printf("Filter Setting Error : Syntex Error!\n");
		pcap_close(fp);
		return -1;
	}
	pcap_loop(fp, 0, packet_handler, NULL);
	pcap_close(fp);
}