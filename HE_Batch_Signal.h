#pragma once
#include "HE_Signal.h"

class HE_Batch_Signal :
	public HE_Signal
{
	size_t slot_count;
	mutable int window_size;
	PolyCRTBuilder *crtbuilder;
	
	/*
	@brief coeficientii filtrului criptati
	intr-un ctxt se afla impachetat un coeficient al filtrului
	de slots ori            ______________________
	filter_enc_coeffs[0] = | a_0| a_0 | ... | a_0 |
	*/
	vector<BigPoly> filter_enc_coeffs;
	vector<BigPoly> encrypted_masks;

	/*
	prelucrarea s-ar putea face si cu un filtru cu coeficienti necriptati
	*/
	vector<int> filtru_necriptat;

public:
	HE_Batch_Signal(const char* poly_modulus = "1x^2048 + 1", int plain_modulus = 1073153,
		int decomposition_bit_count = 32, const char *coeff_modulus = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83");

	~HE_Batch_Signal();

	/*
	@brief seteaza filtrul cu care se va face convolutia
	*/
	void set_filter(vector<int> filter_coeffs);

	void encrypt_signal(vector<int> &signal_coeffs, vector<vector<BigPoly> > &encrypted_windows)const;

	void decrypt_signal(vector<int> &signal_coeffs, vector<BigPoly> &encrypted_signal)const;

	void filter_signal(vector<vector<BigPoly> > &encrypted_windows, vector<BigPoly> &encrypted_signal)const;

};

