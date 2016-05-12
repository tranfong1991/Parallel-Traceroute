/*
Name: Phong Tran
Class: CSCE 463-500
*/

#pragma once
#include<stdio.h>
#include <iostream>

using namespace std;

template<typename ElemType>
class Locator;				//Class declaration

template<typename ElemType>
class Item
{
protected:
	typedef Locator<Item<ElemType>> Locator;
private:
	int key;
	ElemType elem;
	int index;
	Locator* loc;
public:
	Item(int k = -1, ElemType e = ElemType(), Locator* l = NULL)
		: key(k), elem(e), loc(l){}
	Item(const Item& i);

	int getKey() const { return key; }
	ElemType getElem() const { return elem; }
	int getIndex() const { return index; }
	Locator* getLoc() const { return loc; }

	void setKey(int k) { key = k; }
	void setElem(const ElemType& e) { elem = e; }
	void setIndex(int i) { index = i; }
	void setLoc(Item* i) { loc->setItem(i); }

	Item& operator=(const Item& i);
};

template<typename ElemType>
Item<ElemType>::Item(const Item& i)
{
	key = i.key;
	elem = i.elem;
	loc = i.loc;
	loc->setItem(this);
}

template<typename ElemType>
Item<ElemType>& Item<ElemType>::operator=(const Item& i)
{
	key = i.key;
	elem = i.elem;
	loc = i.loc;
	loc->setItem(this);

	return *this;
}

template<typename ElemType>
ostream& operator<<(ostream& os, const Item<ElemType>* i)
{
	os << "(" << i->getKey() << ", " << i->getElem() <<", "<< i->getIndex()<<")";
	return os;
}

template<typename ElemType>
ostream& operator<<(ostream& os, const Item<ElemType>& i)
{
	os << "(" << i.getKey() << ", " << i.getElem() <<", "<<i.getIndex()<< ")";
	return os;
}

template<typename ElemType>
class Locator
{
	ElemType* item;
public:
	Locator(ElemType* i = NULL) : item(i){}

	ElemType* getItem() const { return item; }
	void setItem(ElemType* i) { item = i; }
};

template<typename ElemType>
ostream& operator<<(ostream& os, const Locator<ElemType>& loc)
{
	os << loc.getItem();
	return os;
}

template<typename ElemType>
struct PQComp
{
	int operator() (const Item<ElemType>& e1, const Item<ElemType>& e2)
	{
		return e1.getElem() - e2.getElem();
	}
};

