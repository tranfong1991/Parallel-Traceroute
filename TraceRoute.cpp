/*
Name: Phong Tran
Class: CSCE 463-500
*/

#include "TraceRoute.h"

////query host name concurrently
//DWORD WINAPI dnsRun(LPVOID param)
//{
//	Entry* entry = (Entry*)param;
//
//	struct sockaddr_in sa;
//	memset(&sa, 0, sizeof(sa));
//	sa.sin_family = AF_INET;
//	sa.sin_addr.s_addr = inet_addr(entry->destIp);
//
//	char* hostBuffer = new char[100];
//	if(getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostBuffer, 100, NULL, NULL, NI_NAMEREQD) == 0)
//		entry->destDNSName = hostBuffer;
//
//	return 0;
//}

DWORD WINAPI dnsRun(LPVOID param)
{
	Entry* entry = (Entry*)param;
	
	DNSService dns;
	dns.query(entry->destIp, "8.8.8.8");
	dns.parse(entry->destDNSName);

	return 0;
}

//continuously check for expired packet and retransmit if max attempt is not yet reached.
DWORD WINAPI retxRun(LPVOID param)
{
	RetxThreadParam* p = (RetxThreadParam*)param;

	char* endHostIP = p->endHostIP;
	TraceRoute* traceroute = p->traceroute;
	int& numPacketsReceived = traceroute->numPacketsReceived;
	BinaryHeapPQ<long>& queue = traceroute->retxTimestamps;
	map<USHORT, Entry>& entries = traceroute->entries;

	while (WaitForSingleObject(p->retxFinishEvent, 100) == WAIT_TIMEOUT){
		WaitForSingleObject(p->mutex, INFINITE);
		if (queue.isEmpty()){
			ReleaseMutex(p->mutex);
			continue;
		}

		clock_t now = clock();
		Locator<Item<long>>* loc = queue.getMin();
		int currentSeq = loc->getItem()->getKey();
		long currentTimeOut = loc->getItem()->getElem();

		if (now >= currentTimeOut){
			if (entries[currentSeq - 1].numPacketSent < MAX_RETX_ATTEMPTS){
				sockaddr_in endHost;
				memset(&endHost, 0, sizeof(endHost));
				endHost.sin_family = AF_INET;
				endHost.sin_addr.s_addr = inet_addr(endHostIP);
				endHost.sin_port = htons(80);

				float timeExpired;
				if (entries[currentSeq - 2].rtt != INFINITE && entries[currentSeq].rtt != INFINITE)
					timeExpired = entries[currentSeq - 2].rtt + entries[currentSeq].rtt + traceroute->HOP_TIMEOUT;
				else if (entries[currentSeq - 2].rtt == INFINITE && entries[currentSeq].rtt == INFINITE)
					timeExpired = traceroute->HOP_TIMEOUT * 2;
				else if (entries[currentSeq].rtt == INFINITE)
					timeExpired = entries[currentSeq - 2].rtt * 2 + traceroute->HOP_TIMEOUT;
				else timeExpired = entries[currentSeq].rtt * 2 + traceroute->HOP_TIMEOUT;

				entries[currentSeq - 1].numPacketSent++;
				queue.changeElem(loc, clock() + timeExpired * CLOCKS_PER_SEC / 1000);
				traceroute->sendICMP(currentSeq, endHost);
			}
			else {
				entries[currentSeq - 1].numPacketSent = 4;	//indicate that 3 retx attempts have been made but with no avail
				numPacketsReceived++;
				queue.remove(loc);
			}
		}
		ReleaseMutex(p->mutex);
	}
	return 0;
}

u_short ipChecksum(u_short *buffer, int size)
{
	u_long cksum = 0;

	/* sum all the words together, adding the final byte if size is odd */
	while (size > 1){
		cksum += *buffer++;
		size -= sizeof(u_short);
	}

	if (size)
		cksum += *(u_char *)buffer;

	/* add carry bits to lower u_short word */
	cksum = (cksum >> 16) + (cksum & 0xffff);

	/* return a bitwise complement of the resulting mishmash */
	return (u_short)(~cksum);
}

TraceRoute::TraceRoute() : threadPool(MAX_HOPS), retxTimestamps(MAX_HOPS)
{
	loc = new Locator[MAX_HOPS];

	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);
	sysFreq = float(freq.QuadPart);	//in counts per second

	//setup raw socket
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET){
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}
}

TraceRoute::~TraceRoute()
{
	closesocket(sock);
	delete[] loc;
}

bool TraceRoute::isUniquePacket(USHORT seq)
{
	int prevSize = packetsReceived.size();
	packetsReceived.insert(seq);

	if (prevSize < packetsReceived.size())
		return true;
	return false;
}

char* TraceRoute::queryIP(char* destination)
{
	DWORD ip = inet_addr(destination);
	if (ip == INADDR_NONE){
		struct hostent* remote = gethostbyname(destination);

		if (remote == NULL){
			printf("Failed with %d\n", WSAGetLastError());
			closesocket(sock);
			WSACleanup();
			exit(-1);
		}
		return inet_ntoa(*((struct in_addr *) remote->h_addr));
	}

	return destination;
}

void TraceRoute::sendICMP(USHORT seq, sockaddr_in& endHost)
{
	//buffer for the ICMP header
	u_char sendBuf[MAX_ICMP_SIZE];
	ICMPHeader* icmp = (ICMPHeader*)sendBuf;

	//setup the echo request
	//no need to flip byte order sincer fields are 1 byte each
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;

	//setup ID/SEQ fields
	icmp->id = (u_short)GetCurrentProcessId();
	icmp->seq = seq;

	//initialize checksum to zero
	icmp->checksum = 0;

	int packetSize = sizeof(ICMPHeader);
	icmp->checksum = ipChecksum((u_short*)sendBuf, packetSize);

	//setup proper TTL
	int ttl = seq;
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR){
		printf("setsockopt failed with %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		exit(-1);
	}

	//send icmp packet
	if (sendto(sock, (char*)sendBuf, packetSize, 0, (struct sockaddr*)&endHost, sizeof(endHost)) == SOCKET_ERROR){
		printf("sendto failed with %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		exit(-1);
	}
}

void TraceRoute::receiveICMP(HANDLE mutex, sockaddr_in& endHost)
{
	FD_SET fd;
	struct timeval timeout;

	while (numPacketsReceived < MAX_HOPS){
		u_char receiveBuf[MAX_REPLY_SIZE];

		IPHeader* routerIPHeader = (IPHeader*)receiveBuf;
		ICMPHeader* routerICMPHeader = (ICMPHeader*)(routerIPHeader + 1);
		IPHeader* originIPHeader = (IPHeader*)(routerICMPHeader + 1);
		ICMPHeader* originICMPHeader = (ICMPHeader*)(originIPHeader + 1);

		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		if (select(0, &fd, 0, 0, &timeout) > 0){
			int bytes;
			int len = sizeof(endHost);

			if ((bytes = recvfrom(sock, (char*)receiveBuf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&endHost, &len)) == SOCKET_ERROR){
				printf("recvfrom failed with %d\n", WSAGetLastError());
				closesocket(sock);
				WSACleanup();
				exit(-1);
			}

			//TTL expired packet
			if (bytes >= 56){
				if (originIPHeader->proto == IPPROTO_ICMP && originICMPHeader->id == GetCurrentProcessId()){
					USHORT seq = originICMPHeader->seq;
					char* ip = new char[20];
					ULONG sourceIP = routerIPHeader->source_ip;
					inet_ntop(AF_INET, &sourceIP, ip, 20);

					if (routerICMPHeader->type == ICMP_TTL_EXPIRE && routerICMPHeader->code == 0){	
						WaitForSingleObject(mutex, INFINITE);
						if (isUniquePacket(seq)){
							numPacketsReceived++;
							retxTimestamps.remove(&loc[seq - 1]);
						}
						else {
							ReleaseMutex(mutex);
							continue;
						}
						ReleaseMutex(mutex);

						LARGE_INTEGER stopReceive;
						QueryPerformanceCounter(&stopReceive);
						entries[seq - 1].rtt = float(stopReceive.QuadPart - startReceive.QuadPart) * 1000 / sysFreq;
						entries[seq - 1].destIp = ip;

						//initiate DNS lookup thread
						threadPool.executeAvailableThread(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dnsRun, &entries[seq - 1], 0, NULL));
					}
					//error packet
					else {
						WaitForSingleObject(mutex, INFINITE);
						if (isUniquePacket(seq)){
							numPacketsReceived++;
							retxTimestamps.remove(&loc[seq - 1]);
						}
						else {
							ReleaseMutex(mutex);
							continue;
						}
						ReleaseMutex(mutex);

						char* error;
						int size;
						if (routerICMPHeader->type == ICMP_DEST_UNREACH){
							switch (routerICMPHeader->code){
							case '0':
								error = "Type = 3, Code = 0: Destination network unreachable";
								size = 52;
								break;
							case '1':
								error = "Type = 3, Code = 1: Destination host unreachable";
								size = 49;
								break;
							case '2':
								error = "Type = 3, Code = 2: Destination protocol unreachable";
								size = 53;
								break;
							case '3':
								error = "Type = 3, Code = 3: Destination port unreachable";
								size = 49;
								break;
							default:
								error = "Destination unreachable";
								size = 24;
								break;
							}
						}
						else {
							error = "Unknown Error";
							size = 14;
						}
						entries[seq - 1].destIp = ip;
						entries[seq - 1].errorMsg = new char[size];
						memcpy(entries[seq - 1].errorMsg, error, size);
						threadPool.executeAvailableThread(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dnsRun, &entries[seq - 1], 0, NULL));
					}
				}
			}
			//echo reply packet
			else if ((bytes == 28 || bytes == 32) && routerIPHeader->proto == IPPROTO_ICMP && routerICMPHeader->id == GetCurrentProcessId()){
				if (routerICMPHeader->type == ICMP_ECHO_REPLY && routerICMPHeader->code == 0){
					USHORT seq = routerICMPHeader->seq;

					char* ip = new char[20];
					ULONG sourceIP = routerIPHeader->source_ip;
					inet_ntop(AF_INET, &sourceIP, ip, 20);

					WaitForSingleObject(mutex, INFINITE);
					if (isUniquePacket(seq)){
						//take the first hop that returns echo reply
						if (seq < expectedTotalNum)
							expectedTotalNum = seq;
						numPacketsReceived++;
						retxTimestamps.remove(&loc[seq - 1]);
					}
					else {
						ReleaseMutex(mutex);
						continue;
					}
					ReleaseMutex(mutex);

					LARGE_INTEGER stopReceive;
					QueryPerformanceCounter(&stopReceive);
					entries[seq - 1].rtt = float(stopReceive.QuadPart - startReceive.QuadPart) * 1000 / sysFreq;
					entries[seq - 1].destIp = ip;

					//initiate DNS lookup thread
					threadPool.executeAvailableThread(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dnsRun, &entries[seq - 1], 0, NULL));
				}
			}
		}
	}
}

void TraceRoute::execute(char* destination)
{
	clock_t startTraceRoute = clock();

	char* ip = queryIP(destination);
	printf("Tracerouting to %s...\n", ip);

	//setup end host
	sockaddr_in endHost;
	memset(&endHost, 0, sizeof(endHost));
	endHost.sin_family = AF_INET;
	endHost.sin_addr.s_addr = inet_addr(ip);
	endHost.sin_port = htons(80);

	for (int i = 0; i < MAX_HOPS; i++){
		entries[currentSeq - 1].hopNum = currentSeq;
		entries[currentSeq - 1].numPacketSent = 1;
		retxTimestamps.insert(currentSeq, clock() + HOP_TIMEOUT * CLOCKS_PER_SEC / 1000, &loc[currentSeq - 1]);
		sendICMP(currentSeq++, endHost);
	}

	//create retx thread
	RetxThreadParam retxParam;
	retxParam.mutex = CreateMutex(NULL, 0, NULL);
	retxParam.retxFinishEvent = CreateEvent(NULL, true, false, NULL);
	retxParam.traceroute = this;
	retxParam.endHostIP = ip;
	threadPool.executeAvailableThread(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)retxRun, &retxParam, 0, NULL));

	QueryPerformanceCounter(&startReceive);
	receiveICMP(retxParam.mutex, endHost);

	//set event to end retx thread
	SetEvent(retxParam.retxFinishEvent);
	
	//wait and terminate all running threads, i.e. dns thread and retx thread
	threadPool.closeAllThreads();

	//print trace
	for (int i = 0; i < expectedTotalNum; i++){
		Entry& e = entries[i];

		printf("%2d. ", e.hopNum);

		if (e.errorMsg != NULL){
			if (e.destDNSName != NULL)
				printf("%s (%s)  %s\n", e.destDNSName, e.destIp, e.errorMsg);
			else printf("<no DNS entry> (%s)  %s\n", e.destIp, e.errorMsg);
		} else if (e.numPacketSent <= 3){
			if (e.destDNSName != NULL)
				printf("%s (%s)  %.3f ms  (%d)\n", e.destDNSName, e.destIp, e.rtt, e.numPacketSent);
			else printf("<no DNS entry> (%s)  %.3f ms  (%d)\n", e.destIp, e.rtt, e.numPacketSent);
		}
		else printf("*\n");
	}
	printf("\nFinished tracerouting with %d hops, 30 probes\n", expectedTotalNum);
	printf("Total execution time: %.0f ms\n", (clock() - startTraceRoute) * 1000 / (double)CLOCKS_PER_SEC);
}
