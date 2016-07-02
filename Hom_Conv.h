#pragma once

#include <iostream>
#include <vector>
#include <fstream>
#include "seal.h"

using namespace std;
using namespace seal;

class Hom_Conv
{
	EncryptionParameters parms;
	BigPoly public_key;
	BigPoly secret_key;
	EvaluationKeys evaluation_keys;

	vector<BigPoly> filter;

public:
	Hom_Conv(vector<string> key_files, ofstream &out);

	~Hom_Conv();


	void set_filter(vector<int>& filter);

	void encrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const;

	void decrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const;

	void filter_signal(vector<BigPoly> &in, vector<BigPoly> &out)const;



	void SIMD_set_filter(vector<int>& filter);

	void SIMD_encrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const;

	void SIMD_decrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const;

	void SIMD_filter_signal(vector<BigPoly> &in, vector<BigPoly> &out)const;



	void PF_set_filter(vector<int>& filter);

	void PF_decrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const;

	void PF_filter_signal(vector<BigPoly> &in, vector<BigPoly> &out)const;


	void PF_SIMD_set_filter(vector<int>& filter);

	void PF_SIMD_decrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const;

	void PF_SIMD_filter_signal(vector<BigPoly> &in, vector<BigPoly> &out)const;

};

void test_Hom_Conv(const char *log_file, int N=8, int M=16);

void test_hom_SIMD(const char *log_file, int N = 8, int M = 16);

void test_hom_PF(const char *log_file, int N = 8, int M = 16);

void test_hom_PF_SIMD(const char *log_file, int N = 8, int M = 16);