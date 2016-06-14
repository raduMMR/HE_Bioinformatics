#include "HE_Image.h"
#include <assert.h>
#include <omp.h>


HE_Image::HE_Image(EncryptionParameters &parameters) : 
	parms(parameters),
	crtbuilder(parameters.plain_modulus(), parameters.poly_modulus()) 
{
	kernel_size = 0;
}

HE_Image::~HE_Image() {}

void HE_Image::encrypt_for_filtering(int** &matrix_pixels, int N, vector<vector<BigPoly> > &encrypted_kernels,
	int &slot_count, BigPoly& public_key)const
{
	slot_count = crtbuilder.get_slot_count();

	assert(kernel_size != 0);
	assert((kernel_size % 2) == 1);
	assert(slot_count > 0);

	vector<BigUInt> zero(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	vector<vector<BigUInt> > crt_kernels(kernel_size*kernel_size, zero);

	// !!!! marginile => padding cu zero
	int **padded_matrix = new int*[N + kernel_size];
	for (int i = 0; i < N + kernel_size; i++)
	{
		padded_matrix[i] = new int[N + kernel_size];
		memset(padded_matrix[i], 0, N + kernel_size);
	}
	for (int i = kernel_size / 2; i < N - kernel_size - 2; i++)
	{
		memcpy(padded_matrix[i] + kernel_size / 2, matrix_pixels[i - kernel_size / 2], N);
	}

	int supra_struct_index = 0;
	encrypted_kernels = vector<vector<BigPoly> >(N*N / slot_count);
	int index = 0;
	for (int i = kernel_size/2; i < N-kernel_size/2; i++)
	{
		for (int j = kernel_size/2; j < N- kernel_size/2; j++)
		{
			int k = 0;
			for (int line_index = i - kernel_size / 2; line_index < i + kernel_size/2; line_index++)
			{
				for (int col_index = j - kernel_size / 2; col_index < j+kernel_size/2; col_index++)
				{
					crt_kernels[k++][index] = padded_matrix[line_index][col_index];
				}
			}
			assert(k == kernel_size*kernel_size);
			index = (index + 1) % slot_count;

			if (index == 0)
			{
				for (int si = 0; si < kernel_size*kernel_size; si++)
				{
					// !!! imbunatatire cu omp
					encrypted_kernels[supra_struct_index][si] = crtbuilder.compose(crt_kernels[si]);
				}
				supra_struct_index++;
			}
		}
		
	}

	for (int i = 0; i < N; i++)
	{
		delete[] padded_matrix[i];
	}
	delete[] padded_matrix;
}

void HE_Image::decrypt_after_filtering(int **&matrix_pixels, int N, vector<BigPoly> enc_image,
	int slot_count, BigPoly &secret_key)const
{
	Decryptor decryptor(parms, secret_key);

	matrix_pixels = new int*[N];
	for (int i = 0; i < N; i++)
	{
		BigPoly linie_pixeli = decryptor.decrypt(enc_image[i]);

		matrix_pixels[i] = new int[N];
		for (int j = 0; j < N; j++)
		{
			matrix_pixels[i][j] = crtbuilder.get_slot(linie_pixeli, j).to_double();
		}
	}
}

void HE_Image::encode_filter(int** &kernel, int N, vector<BigPoly> filter,
	int slot_count, BigPoly& public_key)const
{
	assert(slot_count > 0);

	for (int i = 0; i < kernel_size*kernel_size; i++)
	{
		vector<BigUInt> crt_kernel_coeff(slot_count, BigUInt(parms.plain_modulus().bit_count(), 
			static_cast<uint64_t>(   abs(kernel[i/kernel_size][i % kernel_size])  )));

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
	vector<BigPoly> &enc_image, EvaluationKeys& evaluation_keys)const
{
	Evaluator evaluator(parms, evaluation_keys);

#if defined (_OPENMP)

#pragma omp parallel
	{
#pragma omp for shared(encrypted_kernels, filter, original_kernel, enc_image, evaluator, kernel_size) \
		private(i,j, sum, index_sum, sub, index_sub)

		for (int i = 0; i < encrypted_kernels.size(); i++)
		{
			vector<BigPoly> sum; int index_sum = 0;
			vector<BigPoly> sub; int index_sub = 0;

			for (int j = 0; j < kernel_size; j++)
			{
				if (original_kernel[i] < 0)
				{
					sub.push_back(evaluator.multiply_plain(encrypted_kernels[i][j], filter[i]));
					index_sum++;
				}
				else
				{
					sum.push_back(evaluator.multiply_plain(encrypted_kernels[i][j], filter[i]));
					index_sub++;
				}
			}

			BigPoly sumas = evaluator.add_many(sum);
			BigPoly subas = evaluator.add_many(sub);
			enc_image[i] = evaluator.sub(sumas, subas);
		}
	}

#else
	for (int i = 0; i < encrypted_kernels.size(); i++)
	{
		vector<BigPoly> sum; int index_sum = 0;
		vector<BigPoly> sub; int index_sub = 0;

		for (int j = 0; j < kernel_size; j++)
		{
			if (original_kernel[i] < 0)
			{
				sub.push_back(evaluator.multiply_plain(encrypted_kernels[i][j], filter[i]));
				index_sum++;
			}
			else
			{
				sum.push_back(evaluator.multiply_plain(encrypted_kernels[i][j], filter[i]));
				index_sub++;
			}
		}

		BigPoly sumas = evaluator.add_many(sum);
		BigPoly subas = evaluator.add_many(sub);
		enc_image[i] = evaluator.sub(sumas, subas);
	}
#endif
}