/*
Name: Phong Tran
Class: CSCE 463-500
Acknowledgement: homework handout, course powerpoint slides
*/

#pragma once
#include "TraceRoute.h"

int main(int argc, char* argv[])
{
	try{
		if (argc != 2){
			printf("Failed with too few or too many arguments\n");
			return 0;
		}

		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
			printf("WSAStartup error %d\n", WSAGetLastError());
			WSACleanup();
			return 0;
		}

		TraceRoute tr;
		tr.execute(argv[1]);

		printf("\n\n");
		WSACleanup();
		return 0;
	}
	catch (...){
		printf("Unknown Exception!\n");
	}
}