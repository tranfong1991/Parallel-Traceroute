/*
Name: Phong Tran
Class: CSCE 463-500
*/

#pragma once
#include "TraceRoute.h"

//thread container that stores threads, executes available threads, and closes all threads
class ThreadPool{
	HANDLE* threads;
	int capacity;
	int size;
	int currentIndex;
public:
	ThreadPool(int c)
	{
		threads = new HANDLE[c];
		capacity = c;
		size = 0;
		currentIndex = 0;
	}
	~ThreadPool(){ delete[] threads; }

	int getSize() const { return size; }
	void executeAvailableThread(HANDLE handle)
	{
		if (currentIndex == capacity)
			return;

		size++;
		threads[currentIndex++] = handle;
	}
	void closeAllThreads()
	{
		for (int i = 0; i < size; i++){
			WaitForSingleObject(threads[i], INFINITE);
			CloseHandle(threads[i]);
		}
	}
};