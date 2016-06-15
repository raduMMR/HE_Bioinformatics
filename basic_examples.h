#pragma once
#include <iostream>
#include <string>
#include <seal.h>
using namespace std;
using namespace seal;

/* SEAL original examples*/
void example_basics();
void example_weighted_average();
void example_parameter_selection();
void example_batching();
void print_example_banner(string title);

/* MMR's helper functions*/

void generate_parameters(EncryptionParameters &params, BigPoly &public_key,
	BigPoly &secret_key, EvaluationKeys &eval_keys);

void save_parameters(vector<string> filename, EncryptionParameters &params, BigPoly &public_key,
	BigPoly &secret_key, EvaluationKeys &eval_keys);

void load_parameters(vector<string> filename, EncryptionParameters &params, BigPoly &public_key,
	BigPoly &secret_key, EvaluationKeys &eval_keys);

/*********************************************************************************************/

void test_encryption_time();

void test_mix_mult();

void test_mult_time();

void test_reliniarize_after_many_mults();

void test_homomorphic_conv();

void batch_low_param(EncryptionParameters &parms, BigPoly &public_key, BigPoly &secret_key,
	EvaluationKeys &evaluation_keys);

void SEAL_eval_max_depth(EncryptionParameters &parms, BigPoly &public_key, BigPoly &secret_key,
	EvaluationKeys &evaluation_keys);

void conv_parameter_selection(EncryptionParameters &optimal_parms);

void test_real_conv(EncryptionParameters &parms, BigPoly &public_key, BigPoly &secret_key,
	EvaluationKeys &evaluation_keys);


/*
@brief save/load SEAL context parms, pk, sk, ek
****************************************************
@read_write [in]
			true genereaza si salveaza contextul SEAL
			false incarca contextul SEAL
****************************************************
@params [out] parms
@params [out] public_key
@params [out] secret_key
@params [out] evaluation_keys
*/
void SEAL_save_load(bool read_write, EncryptionParameters &parms, BigPoly &public_key,
	BigPoly &secret_key, EvaluationKeys &evaluation_keys);



/*
@brief performs the convolution of the signals
		represented by their associated polynomials
@param [in] v1 first signal
@param [in] v2 the second signal
@param [in] l1 the length of the first signal
@param [in] l2 the length of the second signal
@param [out] res the result of the convolution
@param [out] l the length of the resulted signal
*/
void dummy_convolution(int *v1, int *v2, int l1, int l2, int *&res, int &l);



/*
@brief image sharpening with kernel
		 0 -1  0
		-1  5 -1
		 0 -1  0

!!! kernelul si parametrii schemei se primesc ca params in functie
*/
void hom_image_sharpening();

/*
@brief algoritm de partitionare homomorfice a esantioanelor unui semnal 1D in k clustere

@pursose TEST_ONLY
*/
void hom_k_means();

void test_op(bool load = false);