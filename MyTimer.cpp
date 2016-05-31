#include "MyTimer.h"

void MyTimer::start_timer()
{
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);
}

double MyTimer::stop_timer()
{
	QueryPerformanceCounter(&end);
	double interval = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;

	return interval;
}