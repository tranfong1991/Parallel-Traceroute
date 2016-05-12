/*
Name: Phong Tran
Class: CSCE 463-500
*/

#pragma once
#include<stdio.h>
#include<fstream>
#include<string>
#include"BinaryHeap.h"

template<typename ElemType>
class BinaryHeapPQ
{
protected:
	typedef Item<ElemType> Item;
	typedef PQComp<ElemType> PQComp;
	typedef Locator<Item> Locator;
private:
	BinaryHeap<Item, PQComp> T;
	static const int DEF_SIZE = 7;
public:
	BinaryHeapPQ(int size = DEF_SIZE) : T(size){}
	~BinaryHeapPQ(){}

	void insert(int key, const ElemType& elem, Locator* loc) { T.insert(&Item(key, elem, loc)); }
	Locator* getMin() { return T.findMin().getLoc(); }
	void removeMin() { T.removeMin(); }
	void remove(Locator* loc){ T.remove(loc->getItem()); }
	bool isEmpty() const { return T.isEmpty(); }
	void changeKey(Locator* loc, int k) { loc->getItem()->setKey(k); T.buildHeap(); }
	void changeElem(Locator* loc, ElemType elem) { loc->getItem()->setElem(elem); T.buildHeap(); }
	void showQueue() { T.displayHeap(); }
};

