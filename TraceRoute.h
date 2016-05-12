/*
Name: Phong Tran
Class: CSCE 463-500
*/

#pragma once
#include <iostream>
#include <ctime>
#include <unordered_set>
#include <map>
#include <WS2tcpip.h>
#include "ThreadPool.h"
#include "PacketHeaders.h"
#include "BinaryHeapPQ.h"
#include "DNSService.h"

#define MAX_HOPS 30
#define MAX_RETX_ATTEMPTS 3

using namespace std;

//structure for storing entry information for print out
struct Entry{
	USHORT hopNum = 0;
	USHORT numPacketSent = 0;
	float rtt = INFINITE;
	char* destIp = NULL;
	char* destDNSName = NULL;
	char* errorMsg = NULL;

	Entry(){}
	~Entry(){
		if (destIp != NULL)
			delete[] destIp;
		if (destDNSName != NULL)
			delete[] destDNSName;
		if (errorMsg != NULL)
			delete[] errorMsg;
	}
};

class TraceRoute {
	typedef Locator<Item<long>> Locator;
	const long HOP_TIMEOUT = 500;	//default hop timeout = 500 ms

	SOCKET sock;
	float sysFreq;
	LARGE_INTEGER startReceive;
	int numPacketsReceived = 0;
	int expectedTotalNum = MAX_HOPS;
	USHORT currentSeq = 1;
	ThreadPool threadPool;

	unordered_set<USHORT> packetsReceived;	//to check for duplicate packet
	map<USHORT, Entry> entries;
	Locator* loc;		//for accessing elements inside the priority queue and modifying them
	BinaryHeapPQ<long> retxTimestamps;	//priority queue that stores future retx timestamps

	bool isUniquePacket(USHORT seq);
	char* queryIP(char* destination);
	void sendICMP(USHORT seq, sockaddr_in& endHost);
	void receiveICMP(HANDLE mutex, sockaddr_in& endHost);
public:
	TraceRoute();
	~TraceRoute();

	void execute(char* destination);
	friend DWORD WINAPI retxRun(LPVOID param);
};

struct RetxThreadParam{
	HANDLE mutex;
	HANDLE retxFinishEvent;
	TraceRoute* traceroute;
	char* endHostIP;
};

