#pragma once
#include <iostream>
#include <vector>
#include "seal.h"

using namespace std;
using namespace seal;

// typedef vector<BigPoly> Encrypted_Kernel;
// Encrypted_Kernel
/*						Exemplu
vecin_criptat_0_0 vecin_criptat_0_1 vecin_criptat_0_2
vecin_criptat_1_0       pixel       vecin_criptat_1_2
vecin_criptat_2_0 vecin_criptat_2_1 vecin_criptat_2_2

*/

class HE_Image
{
	EncryptionParameters parms;
	mutable PolyCRTBuilder crtbuilder;

	/*
	@brief dimensiunea kernelului
	*/
	int kernel_size;
public:
	HE_Image(EncryptionParameters &parms, int kernel_size);

	~HE_Image();

	void encrypt_for_filtering(int** &matrix_pixels, int N, vector<vector<BigPoly> > &encrypted_kernels, 
		int &slot_count, BigPoly& public_key)const;

	void decrypt_after_filtering(int *&matrix_pixels, vector<BigPoly> enc_image,
		int slot_count, BigPoly &secret_key)const;

	void omp_decrypt_after_filtering(int *&matrix_pixels, vector<BigPoly> enc_image,
		int slot_count, BigPoly &secret_key)const;

	void encode_filter(int* &kernel, int N, vector<BigPoly> &filter, int slot_count)const;

	void hom_filtering(vector<vector<BigPoly> > &encrypted_kernels, vector<BigPoly> &filter, int original_kernel[],
		vector<BigPoly> &enc_image, EvaluationKeys& evaluation_keys, BigPoly &secret_key)const;

	void omp_hom_filtering(vector<vector<BigPoly> > &encrypted_kernels, vector<BigPoly> &filter, int original_kernel[],
		vector<BigPoly> &enc_image, EvaluationKeys& evaluation_keys, BigPoly &secret_key)const;

	/*PolyCRTBuilder& get_crt_builder()
	{
		return crtbuilder;
	}

	EncryptionParameters& get_enc_params()
	{
		return parms;
	}*/
};

