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


time_t req_start_time;//ù��° request�� ���� �ð�
time_t req_end_time; //������ ������ request�� �� ����
time_t replyStart, replyEnd;
int req_list_count;//req�� ��û�ߴ� host���� ī��Ʈ�� ����
int req_count; //req�� ��û�ߴ� host���� ī��Ʈ�� ����
int rep_list_count;//���� reply list �ȿ� ����ִ� host�� ��
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

	//request�� ���
	if (ntohs(arpheader->op) == 1){
		//������ ��ϵ� �������� �������� �˻�
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
		//���� ó�� ���� request ��Ŷ�� ���
		if (req_count == 0)
		{
			req_start_time = time(0);;
			req_count++;
		}
		//���� ������(������ ������) request ��Ŷ�� ���
		else if (req_count == MAXATTACK - 1)
		{
			req_end_time = time(0);
			req_count++;
		}
		else//1~49�� ���
			req_count++;

		//�ߺ� �˻�
		for (i = 0; i < req_list_count; i++)
		{
			if (!memcmp(&req_list[i].ip, &arpheader->ar_sip, 4))
			{
				req_list[i].count++;
				isExist = 1;
				break;
			}
		}
		if (!isExist)//���� �ߺ��� �ƴϾ��ٸ�
		{//���� ���
			memcpy(&req_list[req_list_count].ip, &arpheader->ar_sip, 4);
			req_list[req_list_count].count++;
			req_list_count++;
		}

		//������ ��Ŷ�� ������ ��� �˻�
		if (req_count == MAXATTACK)
		{//�ð� ���� �˻�
			if (difftime(req_end_time,req_start_time) < 2)
			{//ù ��Ŷ�� ������ ��Ŷ�� �ð� ���̰� 2�� �̸��̾��ٸ�
				//���� �߻�
				for (i = 0; i < req_list_count; i++)
				{//��� ��Ŷ�� ���� ���� ���Գ� �˻�
					if (maxcount < req_list[i].count)
					{
						maxindex = i;
						maxcount = req_list[i].count;
					}
				}
				printf("ȣ��Ʈ ������ '");
				for (i = 0; i < 4; i++)
					printf("%d.", req_list[maxindex].ip[i]);
				printf("'�κ��� arp request attack�� �����Ǿ����ϴ�\n");
				//request attacker list���ٰ� �߰�
				memcpy(req_attackerList.attacker[req_attackerList.attackCount].aip, req_list[maxindex].ip, 4);
				req_attackerList.attackCount++;
			}
			//printf("request �ٽ� ����\n");
			free(req_list);
			req_list = (REQUEST	*)malloc(sizeof(REQUEST) * 100);
			req_list_count = 0;
			req_start_time = 0;
			req_end_time = 0;
			req_count = 0;
		}
	}
	else{
		//attacker�� �������� �˻�
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
		//���� ó�� ���� reply�� ��Ŷ�� ���
		if (rep_count == 0){
			time(&replyStart);
			//printf("reply start : %d\n", replyStart);
			rep_count++;
		}
		//���� �������� ���� reply�� ��Ŷ�� ���
		else if (rep_count == MAXATTACK - 1){
			time(&replyEnd);
			//printf("reply End : %d\n", replyEnd);
			rep_count++;
		}
		else
			rep_count++;

		//���� ó���� ������ ���
		for (i = 0; i < rep_list_count; i++)
		{
			//�ߺ��� ������
			if (!memcmp(rep_list[i].mac, arpheader->ar_sha, 6))
			{
				req_list[i].count++;
				isExist = 1;
				break;
			}
		}
		if (!isExist)//�ߺ��� �ƴ϶�� ���� ����
		{
			memcpy(rep_list[rep_list_count].mac, arpheader->ar_sha, 6);
			rep_list[rep_list_count].count++;
			rep_list_count++;
		}
		if (rep_count == MAXATTACK)
		{
			//�켱 �ð����� ��
			if ((replyEnd - replyStart) <= 1)
			{//ù ��Ŷ�� ������ ��Ŷ�� �ð� ���̰� 1���� �۰ų� ���� ��� �����̴�
				//��� ȣ��Ʈ���� ���� ���� reply�� �Դ��� ã�´�
				for (i = 0; i < rep_list_count; i++)
				{
					if (maxcount < rep_list[i].count)
					{
						maxindex = i;
						maxcount = rep_list[i].count;
					}
				}
				printf("ȣ��Ʈ MAC �ּ� '");
				for (i = 0; i < 6; i++)
					printf("%02X:", rep_list[maxindex].mac[i]);
				printf("'�κ��� arp reply attack�� �����Ǿ����ϴ�\n");
				//reply attacker list���� �߰�
				memcpy(rep_attackerList.attacker[rep_attackerList.attackCount].amac, rep_list[maxindex].mac, 6);
				rep_attackerList.attackCount++;
			}
			printf("Reply �ٽ� ����\n");
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
	bpf_u_int32 netmask = 0, maskp = 0;        // net address, netmask ������ �����Ѵ�.
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