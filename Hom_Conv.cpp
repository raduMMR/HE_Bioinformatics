#include "Hom_Conv.h"
#include "basic_examples.h"
#include <assert.h>
#include "MyTimer.h"
#include <time.h>

Hom_Conv::Hom_Conv(vector<string> key_files, ofstream &out)
{
	load_parameters(key_files, parms, public_key, secret_key, evaluation_keys);

	out << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	/*BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);
	Decryptor decryptor(parms, secret_key);

	BigPoly encoded_coeff;

	Evaluator evaluator(parms, evaluation_keys);

	encoded_coeff = encoder.encode(255);
	BigPoly enc1 = encryptor.encrypt(encoded_coeff);
	enc1 = evaluator.multiply_plain(enc1, encoded_coeff);

	encoded_coeff = decryptor.decrypt(enc1);

	cout << "R : " << encoder.decode_int32(encoded_coeff) << endl;*/
}

Hom_Conv::~Hom_Conv() {}


void Hom_Conv::set_filter(vector<int>& coeffs)
{
	BalancedEncoder encoder(parms.plain_modulus());
	filter = vector<BigPoly>(coeffs.size());
	for (int i = 0; i < coeffs.size(); i++)
	{
		filter[i] = encoder.encode(coeffs[i]);
	}
}

void Hom_Conv::encrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const
{
	BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);
	BigPoly encoded_coeff;

	encrypted_signal = vector<BigPoly>(signal.size());
	for (int i = 0; i < encrypted_signal.size(); i++)
	{
		encoded_coeff = encoder.encode(signal[i]);
		encrypted_signal[i] = encryptor.encrypt(encoded_coeff);
	}
}

void Hom_Conv::decrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const
{
	Decryptor decryptor(parms, secret_key);
	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly encoded_coeff;

	signal = vector<int>(encrypted_signal.size());
	for (int i = 0; i < signal.size(); i++)
	{
		encoded_coeff = decryptor.decrypt(encrypted_signal[i]);
		signal[i] = encoder.decode_int32(encoded_coeff);
	}
}

void Hom_Conv::filter_signal(vector<BigPoly> &in, vector<BigPoly> &out)const
{
	out = vector<BigPoly>(in.size() + filter.size()-1);
	Evaluator evaluator(parms, evaluation_keys);

	BigPoly ip;
	vector<vector<BigPoly>> intermediate_products(out.size());
	for (int i = 0; i < in.size(); i++)
	{
		for (int j = 0; j < filter.size(); j++)
		{
			ip = evaluator.multiply_plain(in[i], filter[j]);
			intermediate_products[i + j].push_back(ip);
		}
	}

	for (int i = 0; i < out.size(); i++)
	{
		out[i] = evaluator.add_many(intermediate_products[i]);
	}
}


void Hom_Conv::SIMD_set_filter(vector<int>& coeffs)
{
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	size_t slot_count = crtbuilder.get_slot_count();
	assert(slot_count >= coeffs.size());

	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	filter = vector<BigPoly>(slot_count-coeffs.size());
	for (int i = 0; i < filter.size(); i++)
	{
		for (int j = i; j < coeffs.size(); j++)
		{
			values[j] = coeffs[j - i];
		}

		filter[i] = crtbuilder.compose(values);

		values[i] = 0;
	}
}

void Hom_Conv::SIMD_encrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const
{
	cout << "TODO : OMP !!!" << endl;

	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	size_t slot_count = crtbuilder.get_slot_count();
	assert(slot_count >= filter.size());

	Encryptor encryptor(parms, public_key);

	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	encrypted_signal = vector<BigPoly>(signal.size());
	for (int i = 0; i < signal.size(); i++)
	{
		for (int j = i % (slot_count - filter.size()); j < i+filter.size(); j++)
		{
			values[j] = signal[i];
		}

		encrypted_signal[i] = encryptor.encrypt(crtbuilder.compose(values));

		// values[i % (slot_count - filter.size())] = 0;
	}
}

void Hom_Conv::SIMD_decrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const
{
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	size_t slot_count = crtbuilder.get_slot_count();

	Decryptor decryptor(parms, secret_key);

	signal = vector<int>(encrypted_signal.size()*slot_count);
	for (int i = 0; i < encrypted_signal.size(); i++)
	{
		BigPoly batched_signal = decryptor.decrypt(encrypted_signal[i]);

		for (int j = 0; j < slot_count; j++)
		{
			signal[i*slot_count+j] = crtbuilder.get_slot(batched_signal, j).to_double();
		}
	}
}

void Hom_Conv::SIMD_filter_signal(vector<BigPoly> &in, vector<BigPoly> &out)const
{
	cout << "ATENTIE !!! Merge doar pentru o dimensiune a vectorului de intrare egala slot_count - filter.size." << endl;
	// out = vector<BigPoly>( ??? );

	Evaluator evaluator(parms, evaluation_keys);

	vector<BigPoly> interm_products;
	for (int i = 0; i < in.size(); i++)
	{
		interm_products.push_back( evaluator.multiply_plain(in[i], filter[i]) );
	}
	out.push_back(evaluator.add_many(interm_products));
}


void Hom_Conv::PF_set_filter(vector<int>& coeffs)
{
	BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);
	filter = vector<BigPoly>(coeffs.size());
	for (int i = 0; i < coeffs.size(); i++)
	{
		filter[i] = encryptor.encrypt(encoder.encode(coeffs[i]));
	}
}

void Hom_Conv::PF_decrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const
{
	Decryptor decryptor(parms, secret_key, 2);
	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly encoded_coeff;

	signal = vector<int>(encrypted_signal.size());
	for (int i = 0; i < signal.size(); i++)
	{
		encoded_coeff = decryptor.decrypt(encrypted_signal[i]);
		signal[i] = encoder.decode_int32(encoded_coeff);
	}
}

void Hom_Conv::PF_filter_signal(vector<BigPoly> &in, vector<BigPoly> &out)const
{
	out = vector<BigPoly>(in.size() + filter.size() - 1);
	Evaluator evaluator(parms, evaluation_keys);

	BigPoly ip;
	vector<vector<BigPoly>> intermediate_products(out.size());
	for (int i = 0; i < in.size(); i++)
	{
		for (int j = 0; j < filter.size(); j++)
		{
			ip = evaluator.multiply_norelin(in[i], filter[j]);
			intermediate_products[i + j].push_back(ip);
		}
	}

	for (int i = 0; i < out.size(); i++)
	{
		out[i] = evaluator.add_many(intermediate_products[i]);
	}
}


void Hom_Conv::PF_SIMD_set_filter(vector<int>& coeffs)
{
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	size_t slot_count = crtbuilder.get_slot_count();
	assert(slot_count >= coeffs.size());

	Encryptor encryptor(parms, public_key);
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(1)));

	filter = vector<BigPoly>(slot_count-coeffs.size());
	for (int i = 0; i < filter.size(); i++)
	{
		/*for (int j = i; j < coeffs.size(); j++)
		{
			values[j] = coeffs[j - i];
		}*/

		filter[i] = encryptor.encrypt(crtbuilder.compose(values));
		values[i] = 0;

/********************************************************************/
		cout << "Filtrul CRT construit INCORECT." << endl;
		for (int j = 1; j < filter.size(); j++)
		{
			filter[j] = filter[0];
		}
		break;
/********************************************************************/
	}
}

void Hom_Conv::PF_SIMD_decrypt_signal(vector<int> &signal, vector<BigPoly> &encrypted_signal)const
{
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	size_t slot_count = crtbuilder.get_slot_count();

	Decryptor decryptor(parms, secret_key, 2);

	signal = vector<int>(encrypted_signal.size()*slot_count);
	for (int i = 0; i < encrypted_signal.size(); i++)
	{
		BigPoly batched_signal = decryptor.decrypt(encrypted_signal[i]);

		for (int j = 0; j < slot_count; j++)
		{
			signal[i*slot_count + j] = crtbuilder.get_slot(batched_signal, j).to_double();
		}
	}
}

void Hom_Conv::PF_SIMD_filter_signal(vector<BigPoly> &in, vector<BigPoly> &out)const
{
	cout << "ATENTIE !!! Merge doar pentru o dimensiune a vectorului de intrare egala slot_count - filter.size." << endl;
	// out = vector<BigPoly>( ??? );
	Evaluator evaluator(parms, evaluation_keys);

	vector<BigPoly> interm_products;
	for (int i = 0; i < in.size(); i++)
	{
		interm_products.push_back( evaluator.multiply_norelin(in[i], filter[i % filter.size()]) );
	}

	out.push_back(evaluator.add_many(interm_products));
}


void test_Hom_Conv()
{
	MyTimer timer;
	ofstream out("test1.txt", ios::out|ios::app);

	vector<vector<string> > files(2, vector<string>(4));
	files[0][0] = "HE_Context/parms4096_batch.out";
	files[0][1] = "HE_Context/pk4096_batch.out";
	files[0][2] = "HE_Context/sk4096_batch.out";
	files[0][3] = "HE_Context/ek4096_batch.out";
	files[1][0] = "HE_Context/parms1024.out";
	files[1][1] = "HE_Context/pk1024.out";
	files[1][2] = "HE_Context/sk1024.out";
	files[1][3] = "HE_Context/ek1024.out";

	for (int i = 0; i < 2; i++)
	{

		Hom_Conv hc(files[i], out);

		vector<int> filter;
		ifstream in("filtru.dat");
		int coeff;
		while (in >> coeff)
		{
			filter.push_back(coeff);
		}
		in.close();

		vector<int> signal(800, 1);
		srand(time(NULL));
		for (int i = 0; i < signal.size(); i++)
		{
			signal[i] = rand() % 511 - 256;
		}

		hc.set_filter(filter);

		vector<BigPoly> enc_signal;

		out << "test_hom_conv " << endl;
		out << "filter.size = " << filter.size() << endl;
		out << "signal.size = " << signal.size() << endl;

		cout << "Se cripteaza semnalul ... " << endl;
		timer.start_timer();
		hc.encrypt_signal(signal, enc_signal);
		double elapsed_time = timer.stop_timer();
		cout << "Timp criptare = " << elapsed_time << " s" << endl;
		out << "Timp criptare = " << elapsed_time << " s" << endl;

		vector<int> result;

		vector<BigPoly> enc_filtered;
		cout << "Se filtreaza semnalul ..." << endl;
		timer.start_timer();
		hc.filter_signal(enc_signal, enc_filtered);
		elapsed_time = timer.stop_timer();
		cout << "Timp convolutie homomorfica = " << elapsed_time << " s" << endl;
		out << "Timp convolutie homomorfica = " << elapsed_time << " s" << endl;

		timer.start_timer();
		hc.decrypt_signal(result, enc_filtered);
		elapsed_time = timer.stop_timer();
		cout << "Timp decriptare = " << elapsed_time << " s" << endl;
		out << "Timp decriptare = " << elapsed_time << " s" << endl;

		/*vector<int> cmp(signal.size()+filter.size()-1 , 0);
		for (int i = 0; i < signal.size(); i++)
		{
			for (int j = 0; j < filter.size(); j++)
			{
				cmp[i + j] += signal[i] * filter[j];
			}
		}

		if (cmp.size() != result.size())
		{
			cout << "cmp.size = " << cmp.size() << " out.size = " << result.size() << endl;
			cout << "Cele doua semnale au dimensiuni diferite." << endl;
			out << "EROARE" << endl;
		}
		else
		{
			bool ok = true;
			for (int i = 0; i < cmp.size(); i++)
			{
				if (cmp[i] != result[i])
				{
					cout << "Coeficienti diferiti: i = " << i;
					cout << ", cmp[i] = " << cmp[i];
					cout << ", out[i] = " << result[i] << endl;
					out << "EROARE" << endl;
					ok = false;
					break;
				}
			}
			if (ok == true)
			{
				cout << "Rezultatele CORECTE." << endl;
			}
		}*/

		out << "*****************************************************" << endl;
	}
	out.close();
}

void test_hom_SIMD()
{
	MyTimer timer;
	ofstream out("test1.txt", ios::out | ios::app);

	vector<vector<string> > files(2, vector<string>(4));
	files[0][0] = "HE_Context/parms4096_batch.out";
	files[0][1] = "HE_Context/pk4096_batch.out";
	files[0][2] = "HE_Context/sk4096_batch.out";
	files[0][3] = "HE_Context/ek4096_batch.out";
	files[1][0] = "HE_Context/parms1024.out";
	files[1][1] = "HE_Context/pk1024.out";
	files[1][2] = "HE_Context/sk1024.out";
	files[1][3] = "HE_Context/ek1024.out";

	for (int i = 0; i < 2; i++)
	{

		Hom_Conv hc(files[i], out);

		vector<int> filter(128, 1);
		/*ifstream in("filtru.dat");
		int coeff;
		while (in >> coeff)
		{
			filter.push_back(coeff);
		}
		in.close();*/

		vector<int> signal(800, 1);
		/*srand(time(NULL));
		for (int i = 0; i < signal.size(); i++)
		{
			signal[i] = rand() % 256;
		}*/

		hc.SIMD_set_filter(filter);

		vector<BigPoly> enc_signal;

		out << "test_hom_SIMD " << endl;
		out << "filter.size = " << filter.size() << endl;
		out << "signal.size = " << signal.size() << endl;

		timer.start_timer();
		hc.SIMD_encrypt_signal(signal, enc_signal);
		double elapsed_time = timer.stop_timer();
		cout << "Timp criptare = " << elapsed_time << " s" << endl;
		// out << "Timp criptare = " << elapsed_time << " s" << endl;

		vector<int> result;

		vector<BigPoly> enc_filtered;
		timer.start_timer();
		hc.SIMD_filter_signal(enc_signal, enc_filtered);
		elapsed_time = timer.stop_timer();
		cout << "Timp convolutie homomorfica = " << elapsed_time << " s" << endl;
		// out << "Timp convolutie homomorfica = " << elapsed_time << " s" << endl;

		timer.start_timer();
		hc.SIMD_decrypt_signal(result, enc_filtered);
		elapsed_time = timer.stop_timer();
		cout << "Timp decriptare = " << elapsed_time << " s" << endl;

		/*vector<int> cmp(signal.size() + filter.size() - 1, 0);
		for (int i = 0; i < signal.size(); i++)
		{
			for (int j = 0; j < filter.size(); j++)
			{
				cmp[i + j] += signal[i] * filter[j];
			}
		}

		if (cmp.size() != result.size())
		{
			cout << "cmp.size = " << cmp.size() << " out.size = " << result.size() << endl;
			cout << "Cele doua semnale au dimensiuni diferite." << endl;
			// out << "EROARE" << endl;
		}
		else
		{
			bool ok = true;
			for (int i = 0; i < cmp.size(); i++)
			{
				if (cmp[i] != result[i])
				{
					cout << "Coeficienti diferiti: i = " << i;
					cout << ", cmp[i] = " << cmp[i];
					cout << ", out[i] = " << result[i] << endl;
					out << "EROARE" << endl;
					ok = false;
					break;
				}
			}
			if (ok == true)
			{
				cout << "Rezultatele CORECTE." << endl;
			}
		}*/

		out << "*****************************************************" << endl;
	}
	out.close();

}

void test_hom_PF()
{
	MyTimer timer;
	ofstream out("test1.txt", ios::out | ios::app);

	vector<vector<string> > files(2, vector<string>(4));
	files[0][0] = "HE_Context/parms4096_batch.out";
	files[0][1] = "HE_Context/pk4096_batch.out";
	files[0][2] = "HE_Context/sk4096_batch.out";
	files[0][3] = "HE_Context/ek4096_batch.out";
	files[1][0] = "HE_Context/parms1024.out";
	files[1][1] = "HE_Context/pk1024.out";
	files[1][2] = "HE_Context/sk1024.out";
	files[1][3] = "HE_Context/ek1024.out";

	for (int i = 0; i < 2; i++)
	{

		Hom_Conv hc(files[i], out);

		vector<int> filter(128, 1);
		/*ifstream in("filtru.dat");
		int coeff;
		while (in >> coeff)
		{
			filter.push_back(coeff);
		}
		in.close();*/

		vector<int> signal(800, 1);
		srand(time(NULL));
		for (int i = 0; i < signal.size(); i++)
		{
			signal[i] = rand() % 511 - 256;
		}

		hc.PF_set_filter(filter);

		vector<BigPoly> enc_signal;

		out << "test_hom_PF " << endl;
		out << "filter.size = " << filter.size() << endl;
		out << "signal.size = " << signal.size() << endl;

		cout << "Se cripteaza semnalul ... " << endl;
		timer.start_timer();
		hc.encrypt_signal(signal, enc_signal);
		double elapsed_time = timer.stop_timer();
		cout << "Timp criptare = " << elapsed_time << " s" << endl;
		out << "Timp criptare = " << elapsed_time << " s" << endl;

		vector<int> result;

		vector<BigPoly> enc_filtered;
		cout << "Se filtreaza semnalul ..." << endl;
		timer.start_timer();
		hc.PF_filter_signal(enc_signal, enc_filtered);
		elapsed_time = timer.stop_timer();
		cout << "Timp convolutie homomorfica = " << elapsed_time << " s" << endl;
		out << "Timp convolutie homomorfica = " << elapsed_time << " s" << endl;

		timer.start_timer();
		hc.PF_decrypt_signal(result, enc_filtered);
		elapsed_time = timer.stop_timer();
		cout << "Timp decriptare = " << elapsed_time << " s" << endl;
		out << "Timp decriptare = " << elapsed_time << " s" << endl;

		/*vector<int> cmp(signal.size() + filter.size() - 1, 0);
		for (int i = 0; i < signal.size(); i++)
		{
			for (int j = 0; j < filter.size(); j++)
			{
				cmp[i + j] += signal[i] * filter[j];
			}
		}

		if (cmp.size() != result.size())
		{
			cout << "cmp.size = " << cmp.size() << " out.size = " << result.size() << endl;
			cout << "Cele doua semnale au dimensiuni diferite." << endl;
			out << "EROARE" << endl;
		}
		else
		{
			bool ok = true;
			for (int i = 0; i < cmp.size(); i++)
			{
				if (cmp[i] != result[i])
				{
					cout << "Coeficienti diferiti: i = " << i;
					cout << ", cmp[i] = " << cmp[i];
					cout << ", out[i] = " << result[i] << endl;
					out << "EROARE" << endl;
					ok = false;
					break;
				}
			}
			if (ok == true)
			{
				cout << "Rezultatele CORECTE." << endl;
			}
		}*/

		out << "*****************************************************" << endl;
	}
	out.close();

}

void test_hom_PF_SIMD()
{
	MyTimer timer;
	ofstream out("test1.txt", ios::out | ios::app);

	vector<vector<string> > files(2, vector<string>(4));
	files[0][0] = "HE_Context/parms4096_batch.out";
	files[0][1] = "HE_Context/pk4096_batch.out";
	files[0][2] = "HE_Context/sk4096_batch.out";
	files[0][3] = "HE_Context/ek4096_batch.out";
	files[1][0] = "HE_Context/parms1024.out";
	files[1][1] = "HE_Context/pk1024.out";
	files[1][2] = "HE_Context/sk1024.out";
	files[1][3] = "HE_Context/ek1024.out";

	for (int i = 0; i < 2; i++)
	{
		Hom_Conv hc(files[i], out);

		vector<int> filter(128, 1);
		/*ifstream in("filtru.dat");
		int coeff;
		while (in >> coeff)
		{
		filter.push_back(coeff);
		}
		in.close();*/

		vector<int> signal(800, 1);
		/*srand(time(NULL));
		for (int i = 0; i < signal.size(); i++)
		{
			signal[i] = rand() % 256;
		}*/

		hc.PF_SIMD_set_filter(filter);

		out << "test_hom_PF_SIMD " << endl;
		out << "filter.size = " << filter.size() << endl;
		out << "signal.size = " << signal.size() << endl;

		vector<BigPoly> enc_signal;

		cout << "Se cripteaza semnalul ... " << endl;
		timer.start_timer();
		hc.SIMD_encrypt_signal(signal, enc_signal);
		double elapsed_time = timer.stop_timer();
		cout << "Timp criptare = " << elapsed_time << " s" << endl;
		out << "Timp criptare = " << elapsed_time << " s" << endl;

		vector<int> result;

		vector<BigPoly> enc_filtered;
		cout << "Se filtreaza semnalul ..." << endl;
		timer.start_timer();
		hc.PF_SIMD_filter_signal(enc_signal, enc_filtered);
		elapsed_time = timer.stop_timer();
		cout << "Timp convolutie homomorfica = " << elapsed_time << " s" << endl;
		out << "Timp convolutie homomorfica = " << elapsed_time << " s" << endl;

		timer.start_timer();
		hc.PF_SIMD_decrypt_signal(result, enc_filtered);
		elapsed_time = timer.stop_timer();
		cout << "Timp decriptare = " << elapsed_time << " s" << endl;
		out << "Timp decriptare = " << elapsed_time << " s" << endl;

		/*vector<int> cmp(signal.size() + filter.size() - 1, 0);
		for (int i = 0; i < signal.size(); i++)
		{
			for (int j = 0; j < filter.size(); j++)
			{
				cmp[i + j] += signal[i] * filter[j];
			}
		}*/

		/*if (cmp.size() != result.size())
		{
			cout << "cmp.size = " << cmp.size() << " out.size = " << result.size() << endl;
			cout << "Cele doua semnale au dimensiuni diferite." << endl;
			out << "EROARE" << endl;
		}
		else
		{*/
		/*bool ok = true;
		for (int i = 0; i < cmp.size(); i++)
		{
			if (cmp[i] != result[i])
			{
				cout << "Coeficienti diferiti: i = " << i;
				cout << ", cmp[i] = " << cmp[i];
				cout << ", result[i] = " << result[i] << endl;
				out << "EROARE" << endl;
				ok = false;
				// break;
			}
		}
		if (ok == true)
		{
			cout << "Rezultatele CORECTE." << endl;
		}*/
		// }

		out << "*****************************************************" << endl;
	}
	out.close();
}