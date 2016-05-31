#pragma once
#include <iostream>
#include <vector>
#include "seal.h"

using namespace std;
using namespace seal;

class HE_Signal
{
protected:
	EncryptionParameters parms;
	BigPoly *secret_key;
	BigPoly *public_key;
	EvaluationKeys *evaluation_keys;

public:

	HE_Signal(const char* poly_modulus = "1x^2048 + 1", int plain_modulus = 1073153,
		int decomposition_bit_count = 32, const char *coeff_modulus = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83");

	virtual ~HE_Signal();

	void encrypt_signal(vector<int> &plain_samples, vector<BigPoly> &encrypted_samples)const;

	void decrypt_signal(vector<int> &plain_samples, vector<BigPoly> &encrypted_samples)const;

	void decrypt_no_relin(vector<int> &plain_samples, vector<BigPoly> &encrypted_samples)const;

	void mult_enc_signals(vector<BigPoly> &enc_s1, vector<BigPoly> &enc_s2, vector<BigPoly> &enc_s)const;

	void conv_window_method(vector<BigPoly> &filter, vector<BigPoly> &signal, vector<BigPoly> &result)const;

};

void read_signal(const char *filename, vector<int> &signal);

void write_signal(const char *filename, vector<int> &signal);

void mult_plain_signals(vector<int> &s1, vector<int> &s2, vector<int> &s_mult);
