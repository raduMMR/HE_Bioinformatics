#pragma once
#include <Windows.h>

class MyTimer
{
	LARGE_INTEGER frequency;
	LARGE_INTEGER start;
	LARGE_INTEGER end;

public:

	void start_timer();

	double stop_timer();
};

