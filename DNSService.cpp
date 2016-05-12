/*
Name: Phong Tran
Class: CSCE 463-500
*/

#include "DNSService.h"

DNSService::DNSService()
{
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET){
		WSACleanup();
		exit(-1);
	}

	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR){
		WSACleanup();
		exit(-1);
	}
}

DNSService::~DNSService()
{
	closesocket(sock);
}

string DNSService::toRRType(USHORT t)
{
	switch (t){
	case DNS_A:
		return "A";
	case DNS_CNAME:
		return "CNAME";
	case DNS_NS:
		return "NS";
	case DNS_PTR:
		return "PTR";
	case DNS_HINFO:
		return "HINFO";
	case DNS_MX:
		return "MX";
	case DNS_AXFR:
		return "AXFR";
	default:
		return "ANY";
	}
}

//reverse ip and copy it into buf
void DNSService::reverseIp(char* buf, char* ip, int len)
{
	char* copyStr = new char[strlen(ip) + 1];
	Utils::myStrCopy(ip, copyStr, strlen(ip) + 1);

	stack<char*> st;
	char* ptr = copyStr;
	char* front = ptr;

	while (true){
		ptr = strchr(ptr, '.');

		if (ptr == NULL){
			st.push(front);
			break;
		}
		*ptr = 0;
		st.push(front);

		ptr++;
		front = ptr;
	}

	char* p = buf;
	while (!st.empty()){
		char* top = st.top();
		st.pop();

		Utils::myStrCopy(top, p, strlen(top));
		*(p + strlen(top)) = '.';
		p += strlen(top) + 1;
	}
	Utils::myStrCopy("in-addr.arpa\0", p, 13);

	delete[] copyStr;
}

//construct name for dns look up
void DNSService::makeDNSQuestion(char* buf, char* host)
{
	char* bufPtr = buf;
	char* hostPtr = host;
	char* front = hostPtr;

	while (true){
		hostPtr = strchr(hostPtr, '.');

		if (hostPtr == NULL){
			*bufPtr = strlen(front);
			Utils::myStrCopy(front, bufPtr + 1, strlen(front));
			bufPtr += strlen(front) + 1;
			break;
		}

		*bufPtr = hostPtr - front;
		Utils::myStrCopy(front, bufPtr + 1, hostPtr - front);

		bufPtr += hostPtr - front + 1;
		hostPtr++;
		front = hostPtr;
	}
	*bufPtr = 0;
}

//turn bits into ip string
string DNSService::toIP(unsigned char* ptr, int len)
{
	string result;
	unsigned char* srcPtr = ptr;

	for (int i = 0; i < len; i++){
		//missing character, return empty string
		if (*srcPtr == 0 && i < len - 1)
			return string();

		result += to_string((int)(*srcPtr));
		if (i != len - 1)
			result += ".";
		srcPtr++;
	}
	return result;
}

//turn bits into readable name
unsigned char* DNSService::resolveName(unsigned char* buf, unsigned char* name, char* response)
{
	int i = 0;
	unsigned int size = 0;

	while (true){
		if (i % 2 == 0){
			size = *name;
		}
		else {
			if (size >= 0xc0){
				if (name[1] == 0 && name[2] >= 0xcc)
					return NULL;

				int offset = ((~(0xc0) & size) << 8) + name[1];
				if (offset < sizeof(DNSHeader))
					return NULL;

				if (offset >= bytes)
					return NULL;

				name = (unsigned char*)((unsigned char*)response + offset);
				buf = resolveName(buf, name, response);
				if (buf == NULL)
					return NULL;
				break;
			}
			else {
				if (Utils::myStrCopy((char*)(name + 1), (char*)buf, size) < 0)
					return NULL;

				*(buf + size) = '.';
				buf += size + 1;
				name += size + 1;

				if (*(name + 1) == 0xcc)
					return NULL;
				
				if (*name == 0){
					*(--buf) = 0;
					break;
				}
			}
		}
		i++;
	}
	return buf;
}

bool DNSService::readQuestion(unsigned char*& content, ResourceRecord* resourceRecord, int n)
{
	int iteration = 0;

	while (iteration++ < n){
		unsigned char* name = content;
		unsigned char* properName = new unsigned char[MAX_DNS_SIZE];
		if (resolveName(properName, name, responseBuf) == NULL){
			delete[] properName;
			return false;
		}
		resourceRecord = (ResourceRecord*)(name + strlen((char*)name) + 1);

		name += strlen((char*)name) + 5;	//skip the query header
		content = name;
		delete[] properName;
	}
	return true;
}

bool DNSService::readAnswer(unsigned char*& content, ResourceRecord* resourceRecord, char*& dnsName)
{
	int iteration = 0;
	unsigned char* name = content;

	unsigned char* properName = new unsigned char[MAX_DNS_SIZE];
	if (resolveName(properName, name, responseBuf) == NULL){
		delete[] properName;
		return false;
	}

	//find RR field
	while (*content < 0xc0 && *content != 0)
		content++;
	resourceRecord = (ResourceRecord*)(*content == 0 ? content + 1 : content + 2);

	string rType = toRRType(ntohs(resourceRecord->rType));
	USHORT rLength = ntohs(resourceRecord->rLength);

	if (rType == "PTR" || rType == "CNAME" || rType == "NS"){
		unsigned char* dn = (unsigned char*)(&(resourceRecord->rLength) + 1);
		unsigned char* properDN = new unsigned char[MAX_DNS_SIZE];
		if (resolveName(properDN, dn, responseBuf) == NULL){
			delete[] properName;
			delete[] properDN;
			return false;
		}
		dnsName = (char*)properDN;
	}
	else if (rType == "A"){
		string addr = toIP((unsigned char*)(&(resourceRecord->rLength) + 1), rLength);
	}

	content = rLength + (unsigned char*)(&(resourceRecord->rLength) + 1);
	delete[] properName;
	return true;
}

//sends request and stores the answer
bool DNSService::query(char* host, char* dns)
{
	int size = strlen(host) + 2 + sizeof(DNSHeader) + sizeof(QueryHeader);
	DWORD ip = inet_addr(host);
	//in case of reverse lookup, the length is 13 characters more because of .in-addr.arpa
	if (ip != INADDR_NONE)
		size += 13;

	char* buf = new char[size];
	DNSHeader* dnsHeader = (DNSHeader*)buf;
	QueryHeader* queryHeader = (QueryHeader*)(buf + size - sizeof(QueryHeader));

	//construct header
	dnsHeader->id = htons(currentId);
	dnsHeader->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
	dnsHeader->nQuestions = htons(1);
	dnsHeader->nAnswers = 0;
	dnsHeader->nAuthority = 0;
	dnsHeader->nAdditional = 0;

	//print query
	if (ip == INADDR_NONE){
		makeDNSQuestion((char*)(dnsHeader + 1), host);
		queryHeader->qType = htons(DNS_A);
	}
	else {
		char* reversedHost = new char[strlen(host) + 14];
		reverseIp(reversedHost, host, strlen(host));
		makeDNSQuestion((char*)(dnsHeader + 1), reversedHost);

		queryHeader->qType = htons(DNS_PTR);
		delete[] reversedHost;
	}
	queryHeader->qClass = htons(DNS_INET);

	struct sockaddr_in dnsServer;
	memset(&dnsServer, 0, sizeof(dnsServer));
	dnsServer.sin_family = AF_INET;
	dnsServer.sin_addr.s_addr = inet_addr(dns); // server’s IP
	dnsServer.sin_port = htons(53);	// DNS port on server

	FD_SET fd;
	struct timeval timeout;
	int count = 0;
	int start, end;
	while (count < MAX_ATTEMPTS){
		start = clock();
		if (sendto(sock, buf, size, 0, (struct sockaddr*)&dnsServer, sizeof(dnsServer)) == SOCKET_ERROR){
			delete[] buf;
			return false;
		}
		
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		int ret;
		if ((ret = select(0, &fd, 0, 0, &timeout)) > 0){
			int len = sizeof(dnsServer);

			struct sockaddr_in response;
			if ((bytes = recvfrom(sock, responseBuf, MAX_DNS_SIZE, 0, (struct sockaddr*)&response, &len)) == SOCKET_ERROR){
				delete[] buf;
				return false;
			}
			if (bytes < MAX_DNS_SIZE)
				responseBuf[bytes] = 0;

			//check for malicious server
			if (memcmp(&response.sin_addr, &dnsServer.sin_addr, sizeof(DWORD)) != 0 || response.sin_port != dnsServer.sin_port){
				delete[] buf;
				return false;
			}
			end = clock();

			closesocket(sock);
			break;
		}
		else if (ret == 0){
			delete[] buf;
			return false;
		}
		else {
			delete[] buf;
			return false;
		}
	}
	delete[] buf;

	if (count == MAX_ATTEMPTS)
		return false;
	return true;
}

//parse response
void DNSService::parse(char*& dnsName)
{
	DNSHeader* dnsHeader = (DNSHeader*)responseBuf;
	USHORT id = ntohs(dnsHeader->id);
	USHORT flags = ntohs(dnsHeader->flags);
	USHORT nQuestions = ntohs(dnsHeader->nQuestions);
	USHORT nAnswers = ntohs(dnsHeader->nAnswers);
	USHORT nAuthority = ntohs(dnsHeader->nAuthority);
	USHORT nAdditional = ntohs(dnsHeader->nAdditional);

	//get reply code
	USHORT replyCode = (~(~0 << 4)) & flags;
	if (replyCode != DNS_OK)
		return;

	ResourceRecord* resourceRecord = NULL;
	unsigned char* content = (unsigned char*)(dnsHeader + 1);

	//question section
	if (nQuestions > 0){
		if (!readQuestion(content, resourceRecord, nQuestions))
			return;
	}

	//answer section
	if (nAnswers > 0){
		if (!readAnswer(content, resourceRecord, dnsName))
			return;
	}
}