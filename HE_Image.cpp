#include "HE_Image.h"
#include <assert.h>
#include <omp.h>


HE_Image::HE_Image(EncryptionParameters &parameters, int ks) : 
	parms(parameters),
	crtbuilder(parameters.plain_modulus(), parameters.poly_modulus()),
	kernel_size(ks)
{
	cout << "FUNCTIONEAZA DOAR PENTRU FILTRE DE DETECTIE A CONTURURILOR." << endl;
}

HE_Image::~HE_Image() {}

void HE_Image::encrypt_for_filtering(int** &matrix_pixels, int N, vector<vector<BigPoly> > &encrypted_kernels,
	int &slot_count, BigPoly& public_key)const
{
	slot_count = crtbuilder.get_slot_count();

	assert(kernel_size != 0);
	assert((kernel_size % 2) == 1);
	assert(slot_count > 0);

	Encryptor encryptor(parms, public_key);

	vector<BigUInt> zero(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	vector<vector<BigUInt> > crt_kernels(kernel_size*kernel_size, zero);

	// !!!! marginile => padding cu zero
	int **padded_matrix = new int*[N + kernel_size];
	for (int i = 0; i < N + kernel_size; i++)
	{
		padded_matrix[i] = new int[N + kernel_size];
		memset(padded_matrix[i], 0, sizeof(int) *( N + kernel_size) );
	}
	for (int i = kernel_size / 2; i < N - kernel_size/2; i++)
	{
		memcpy( (padded_matrix + kernel_size / 2)[i] , matrix_pixels[i - kernel_size/2], N);
	}

	int index = 0;
	for (int i = kernel_size/2; i < N-kernel_size/2; i++)
	{
		for (int j = kernel_size/2; j < N- kernel_size/2; j++)
		{
			int k = 0;
			for (int line_index = i - kernel_size / 2; line_index < i + kernel_size/2 + 1; line_index++)
			{
				for (int col_index = j - kernel_size / 2; col_index < j+kernel_size/2 + 1; col_index++)
				{
					crt_kernels[k++][index] = padded_matrix[line_index][col_index];
				}
			}
			// cout << "k = " << k << endl;
			assert(k == kernel_size*kernel_size);
			index = (index + 1) % slot_count;

			if (index == 0)
			{
				// au fost completate toate cele slot_count sloturi din cei kernel_size vectori
				// => putem cripta
				// crt_kernel[0] - vecinii din stanga sus a celor 1024 de pixeli s.a.m.d.

				vector<BigPoly> this_round;
				for (int si = 0; si < kernel_size*kernel_size; si++)
				{
					// !!! imbunatatire cu omp
					// this_round.push_back(crtbuilder.compose(crt_kernels[kernel_size / 2]));


					
					// #ifdef TEST
					BigPoly bp = crtbuilder.compose(crt_kernels[kernel_size / 2]);
					bp = encryptor.encrypt(bp);

					for (int di = 0; di < kernel_size*kernel_size; di++)
					{
						this_round.push_back(bp);
					}
					break;
					// #endif
				}
				// encrypted_kernels.push_back(this_round);

				// #ifdef TEST
				for (int i = 0; i < N*N/slot_count; i++)
				{
					encrypted_kernels.push_back(this_round);
				}
				j = N - kernel_size / 2;
				i = N - kernel_size / 25;
				// #endif
			}
		}
		
	}

	for (int i = 0; i < N; i++)
	{
		delete[] padded_matrix[i];
	}
	delete[] padded_matrix;
}

void HE_Image::decrypt_after_filtering(int *&matrix_pixels, vector<BigPoly> enc_image,
	int slot_count, BigPoly &secret_key)const
{
	Decryptor decryptor(parms, secret_key);
	slot_count = crtbuilder.get_slot_count();

	matrix_pixels = new int[enc_image.size() * slot_count];

	for (int i = 0; i < enc_image.size(); i++)
	{
		BigPoly linie_pixeli = decryptor.decrypt(enc_image[i]);

		for (int j = 0; j < slot_count; j++)
		{
			matrix_pixels[i * enc_image.size() + j ] = crtbuilder.get_slot(linie_pixeli, j).to_double();
		}
	}
}

void HE_Image::encode_filter(int* &kernel, int N, vector<BigPoly> &filter,
	int slot_count)const
{
	assert(slot_count > 0);

	filter = vector<BigPoly>(kernel_size*kernel_size);

	for (int i = 0; i < kernel_size*kernel_size; i++)
	{
		vector<BigUInt> crt_kernel_coeff(slot_count, BigUInt(parms.plain_modulus().bit_count(), 
			static_cast<uint64_t>(   abs(kernel[ i/kernel_size * kernel_size + i % kernel_size])  )));

#if defined (_OPENMP)
#pragma omp parallel
		{
#pragma omp for shared(crt_kernel_coeff, i, filter) private(j)
			for (int j = 0; j < slot_count; j++)
			{
				crtbuilder.set_slot(crt_kernel_coeff[j], j, filter[i]);
			}
		}
#else
		filter[i] = crtbuilder.compose(crt_kernel_coeff);
#endif
	}
}

void HE_Image::hom_filtering(vector<vector<BigPoly> > &encrypted_kernels, vector<BigPoly> &filter, int original_kernel[], 
	vector<BigPoly> &enc_image, EvaluationKeys& evaluation_keys, BigPoly &secret_key)const
{
	Evaluator evaluator(parms, evaluation_keys);
	enc_image = vector<BigPoly>(encrypted_kernels.size());

	for (int i = 0; i < encrypted_kernels.size(); i++)
	{
		vector<BigPoly> sum; int index_sum = 0;
		vector<BigPoly> sub; int index_sub = 0;

		for (int j = 0; j < kernel_size; j++)
		{
			if (original_kernel[j] < 0)
			{
				sub.push_back(evaluator.multiply_plain(encrypted_kernels[i][j], filter[j]));
				index_sum++;
			}
			else
			{
				sum.push_back(evaluator.multiply_plain(encrypted_kernels[i][j], filter[j]));
				index_sub++;
			}
		}

		BigPoly sumas = evaluator.add_many(sum);
		BigPoly subas = evaluator.add_many(sub);

		enc_image[i] = evaluator.sub(sumas, subas);
	}
}






/*******************************                 omp routines                   ********************************************/
void HE_Image::omp_hom_filtering(vector<vector<BigPoly> > &encrypted_kernels, vector<BigPoly> &filter, int original_kernel[],
	vector<BigPoly> &enc_image, EvaluationKeys& evaluation_keys, BigPoly &secret_key)const
{
	Evaluator evaluator(parms, evaluation_keys);
	enc_image = vector<BigPoly>(encrypted_kernels.size());

#pragma omp parallel
	{
// #pragma omp for shared(encrypted_kernels, filter, original_kernel, enc_image, evaluator, kernel_size) \
		private(i,j, sum, index_sum, sub, index_sub, sumas, subas)

		for (int i = 0; i < encrypted_kernels.size(); i++)
		{
			vector<BigPoly> sum; int index_sum = 0;
			vector<BigPoly> sub; int index_sub = 0;

#pragma omp for shared(encrypted_kernels, filter, original_kernel, enc_image, sumas, subas,  \
		evaluator, kernel_size, sum, index_sum, sub, index_sub, ) \
		private(j)
			for (int j = 0; j < kernel_size*kernel_size; j++)
			{
				if (original_kernel[j] < 0)
				{
					sub.push_back(evaluator.multiply_plain(encrypted_kernels[i][j], filter[j]));
					index_sum++;
				}
				else
				{
					sum.push_back(evaluator.multiply_plain(encrypted_kernels[i][j], filter[j]));
					index_sub++;
				}
			}

			BigPoly sumas = evaluator.add_many(sum);
			BigPoly subas = evaluator.add_many(sub);
			enc_image[i] = evaluator.sub(sumas, subas);
		}
	}
}

void HE_Image::omp_decrypt_after_filtering(int *&matrix_pixels, vector<BigPoly> enc_image,
	int slot_count, BigPoly &secret_key)const
{
	Decryptor decryptor(parms, secret_key);
	slot_count = crtbuilder.get_slot_count();

	matrix_pixels = new int[enc_image.size() * slot_count];

#pragma omp parallel
	{
#pragma omp for shared(enc_image, crtbuilder, matrix_pixels, slot_count) private(linie_pixeli, i, j)
		for (int i = 0; i < enc_image.size(); i++)
		{
			BigPoly linie_pixeli = decryptor.decrypt(enc_image[i]);
			for (int j = 0; j < slot_count; j++)
			{
				matrix_pixels[i * enc_image.size() + j] = crtbuilder.get_slot(linie_pixeli, j).to_double();
			}
		}
	}
}
