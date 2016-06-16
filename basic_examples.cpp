#include "basic_examples.h"
#include <iostream>
#include <seal.h>
#include "MyTimer.h"
#include <time.h>
#include "HE_Batch_Signal.h"
#include <fstream>
#include <assert.h>
#include <string>
#include "HE_Image.h"

using namespace std;
using namespace seal;



/* MMR's helper functions*/
void generate_parameters(EncryptionParameters &parms, BigPoly &public_key,
	BigPoly &secret_key, EvaluationKeys &evaluation_keys)
{
	// assert(params == setat)

	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;

	public_key = generator.public_key();
	secret_key = generator.secret_key();
	evaluation_keys = generator.evaluation_keys();
}

void save_parameters(vector<string> filename, EncryptionParameters &parms, BigPoly &public_key,
	BigPoly &secret_key, EvaluationKeys &evaluation_keys)
{
	ofstream out(filename[0], ios::out | ios::binary);
	parms.save(out);
	out.close();
	out.open(filename[1], ios::out | ios::binary);
	public_key.save(out);
	out.close();
	out.open(filename[2], ios::out | ios::binary);
	secret_key.save(out);
	out.close();
	out.open(filename[3], ios::out | ios::binary);
	evaluation_keys.save(out);
	out.close();
}

void load_parameters(vector<string> filename, EncryptionParameters &parms, BigPoly &public_key,
	BigPoly &secret_key, EvaluationKeys &evaluation_keys)
{
	assert(filename.size() == 4);

	ifstream in(filename[0], ios::in | ios::binary);
	parms.load(in);
	in.close();
	in.open(filename[1], ios::in | ios::binary);
	public_key.load(in);
	in.close();
	in.open(filename[2], ios::in | ios::binary);
	secret_key.load(in);
	in.close();
	in.open(filename[3], ios::in | ios::binary);
	evaluation_keys.load(in);
	in.close();
}

/*********************************************************************************************/

void test_real_conv(EncryptionParameters &parms1, BigPoly &public_key1, BigPoly &secret_key1,
	EvaluationKeys &evaluation_keys1)
{
	MyTimer timer;

//#error 
	/* calculeaza parametrii pentru batching */

	EncryptionParameters parms;
	parms.poly_modulus() = "1x^1024 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	// parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(1024);
	parms.plain_modulus() = 1073153;
	// parms.plain_modulus() = 6507521;
	parms.decomposition_bit_count() = 4;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encryption tools
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key);

	cout << "CRT building ..." << endl;
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	cout << "CRT finished." << endl;

	size_t slot_count = crtbuilder.get_slot_count();
	cout << "slot_count = " << slot_count << endl;

	int esantion = 1;
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(esantion)));

	BigPoly plain_composed_poly = crtbuilder.compose(values);

	BigPoly crt_ctxt = encryptor.encrypt(plain_composed_poly);

	crt_ctxt = evaluator.multiply(crt_ctxt, crt_ctxt);
	esantion *= esantion;

	BigPoly decrypted = decryptor.decrypt(crt_ctxt);
	if (crtbuilder.get_slot(decrypted, 0).to_double() != esantion)
	{
		cout << "Eroare la prima inmultire." << endl;
	}

	// timer.start_timer();

	vector<BigUInt> masca(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(1)));
	masca[0] = 0;

	cout << endl << endl;

	esantion = 0;
	BigPoly result = crt_ctxt;
	bool ok = true;
	for (int i = 0; i < 15; i++)
	{
		BigPoly masca_coeff_poly = crtbuilder.compose(masca); // // Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
		result = evaluator.multiply_plain(result, masca_coeff_poly); 
		result = evaluator.add(result, crt_ctxt); esantion += 1 * 1;

		decrypted = decryptor.decrypt(result);
		for (int j = 0; j < 15; j++)
		{
			int res = crtbuilder.get_slot(decrypted, j).to_double();
			cout << res << " ";
		}
		cout << endl;
		for (int j = 0; j < 15; j++)
		{
			int res = crtbuilder.get_slot(masca_coeff_poly, j).to_double();
			cout << res << " ";
		}
		cout << endl << endl;
		// int res = crtbuilder.get_slot(decrypted, 0).to_double();
		// if ( res != esantion)
		// {
			// cout << "plain_0[" << i << "] = " << res << endl;
			// cout << "masca0 = " << masca[0].to_double() << endl;
			// cout << "Eroare la iteratia " << i << endl;
			ok = false;
			// break;
		// }

		masca[i] = 1;
		if (i + 1 < masca.size())
		{
			masca[i + 1] = 0;
		}
	}

	if (ok == true)
	{
		decrypted = decryptor.decrypt(crt_ctxt);

		int res = crtbuilder.get_slot(decrypted, 0).to_double();

		if ( res != 255 * 255 * 15)
		{
			cout << "Rezultat final = " << res << endl;
			cout << "Eroare la rezultatul final." << endl;
		}
		else
		{
			cout << "GREAT SUCCES :)" << endl;
		}
	}
}


void SEAL_eval_max_depth(EncryptionParameters &parms, BigPoly &public_key, BigPoly &secret_key,
	EvaluationKeys &evaluation_keys)
{
	MyTimer timer;

	/*EncryptionParameters parms;
	parms.poly_modulus() = "1x^1024 + 1";
	// parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(1024);
	parms.plain_modulus() = 1 << 8;      //  6507521;
	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();*/

	// Create the encryption tools
	BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	

	BigPoly encoded = encoder.encode(1);
	BigPoly encrypted = encryptor.encrypt(encoded);
	BigPoly decrypted;
	BigPoly product = encrypted;

	for (int i = 0; i < 1024; i++)
	{
		Decryptor decryptor(parms, secret_key, 1 + i);
		decrypted = decryptor.decrypt(product);
		if (encoder.decode_int32(decrypted) != 1)
		{
			cout << "Max mult depth = " << i << endl << endl;
			break;
		}

		product = evaluator.multiply_norelin(product, encrypted);

		cout << i << endl;
	}

	cout << "Final test max depth." << endl << endl;
}

// maxim 16 adunari de 255*255 pt setarile de mai jos
void batch_low_param(EncryptionParameters &parms1, BigPoly &public_key1, BigPoly &secret_key1,
	EvaluationKeys &evaluation_keys1)
{
	MyTimer timer;

	EncryptionParameters parms;
	parms.poly_modulus() = "1x^1024 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	// parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(1024);
	parms.plain_modulus() = 1073153;
	// parms.plain_modulus() = 6507521;
	parms.decomposition_bit_count() = 4;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encryption tools
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key);

	cout << "CRT building ..." << endl;
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	cout << "CRT finished." << endl;

	size_t slot_count = crtbuilder.get_slot_count();
	cout << "slot_count = " << slot_count << endl;

	int esantion = 1;
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(esantion)));

	vector<BigUInt> masca(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(1)));
	masca[0] = 3;

	BigPoly plain_composed_poly = crtbuilder.compose(values);

	BigPoly crt_ctxt = encryptor.encrypt(plain_composed_poly);

	crt_ctxt = evaluator.multiply(crt_ctxt, crt_ctxt);
	esantion *= esantion;

	BigPoly decrypted = decryptor.decrypt(crt_ctxt);
	if (crtbuilder.get_slot(decrypted, 0).to_double() != esantion)
	{
		cout << "Eroare la prima inmultire." << endl;
	}

	// timer.start_timer();

	bool ok = true;
	for (int i = 0; i<8; i++)
	{
		BigPoly masca_coeff_poly = crtbuilder.compose(masca); // // Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
		BigPoly result = evaluator.multiply_plain(crt_ctxt, masca_coeff_poly);
		result = evaluator.add(result, crt_ctxt);
		
		decrypted = decryptor.decrypt(crt_ctxt);

		if (crtbuilder.get_slot(decrypted, i).to_double() != esantion )
		{
			cout << "Eroare la iteratia " << i << endl;
			ok = false;
			break;
		}

		masca[i] = 1;
		if (i + 1 < masca.size())
		{
			masca[i + 1] = 0;
		}
	}	

	if (ok == true)
	{
		cout << "SUCCES :)" << endl;
	}
	
	// vector<BigPoly> coloana(16, crt_ctxt);
	// crt_ctxt = evaluator.add_many(coloana);

	// cout << "Timp inmultire batch CU reliniarizare = " << timer.stop_timer() / 20 << endl << endl;

	/*decrypted = decryptor.decrypt(crt_ctxt);

	cout << "crt_ctxt = [ ";
	for (int i = 0; i < 3; i++)
	{
		cout << crtbuilder.get_slot(decrypted, i).to_double() << " ";
	}
	cout << "]" << endl;*/

	/*timer.start_timer();
	for (int i = 0; i < 20; i++)
	{
		evaluator.multiply_norelin(crt_ctxt, crt_ctxt);
	}

	cout << "Timp inmultire batch FARA reliniarizare = " << timer.stop_timer() / 20 << endl << endl;*/
}

void test_homomorphic_conv()
{
	HE_Batch_Signal he_signal("1x^1024 + 1");

	vector<int> filtru(4, 1);
	/*filtru[0] = 0;
	filtru[1] = 1;
	filtru[2] = 3;
	filtru[3] = 2;*/

	vector<int> semnal(4);
	for (int i = 0; i < 4; i++)
	{
		semnal[i] = i;
	}

	vector<vector<BigPoly> > windows;

	he_signal.set_filter(filtru);

	he_signal.encrypt_signal(semnal, windows);

	vector<BigPoly> enc_filtered_signal;
	he_signal.filter_signal(windows, enc_filtered_signal);

	vector<int> plain_filtered_signal;
	he_signal.decrypt_signal(plain_filtered_signal, enc_filtered_signal);

	/*vector<BigPoly> test(1, windows[0][0]);
	cout << "Semnal decriptat " << endl;
	vector<int> check;
	he_signal.decrypt_signal(check, test);
	for (int i = 0; i < check.size(); i++)
	{
		cout << check[i] << endl;
	}
	cout << endl;*/

	vector<int> cmp_result;
	mult_plain_signals(filtru, semnal, cmp_result);

	/*bool ok = true;
	for (int i = 0; i < cmp_result.size(); i++)
	{
		if (cmp_result[i] != plain_filtered_signal[i])
		{
			cout << "Rezultatele difera\n";
			ok = false;
			cout << "cmp_result[" << i << "] = " << cmp_result[i] << "\t";
			cout << "he_signal[" << i << "] = " << plain_filtered_signal[i] << endl;
			// break;
		}
	}

	if (ok == true)
	{
		cout << "SUCCES ! Convolutie corecta.\n";
	}*/
}

void test_reliniarize_after_many_mults()
{
	MyTimer timer;

	EncryptionParameters parms;
	parms.poly_modulus() = "1x^2048 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1 << 8;
	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encryption tools
	BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key, 5);

	BigPoly encoded = encoder.encode(3);
	BigPoly ct = encryptor.encrypt(encoded);

	vector<BigPoly> encs(5, ct);
	// timer.start_timer();
	ct = evaluator.multiply_norelin_many(encs);
	// ct = evaluator.relinearize(ct);
	// cout << "Timp mult_many + reliniarize = " << timer.stop_timer() << endl << endl;

	BigPoly decrypted = decryptor.decrypt(ct);

	cout << "Result = " << encoder.decode_int32(decrypted) << endl << endl;

}

void test_mix_mult()
{
	MyTimer timer;

	EncryptionParameters parms;
	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	// parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1073153;
	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encryption tools
	BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key);

	BigPoly ptxt1 = encoder.encode(1);
	BigPoly ptxt2 = encoder.encode(10);

	BigPoly ct1 = encryptor.encrypt(ptxt1);
	BigPoly ct2 = encryptor.encrypt(ptxt2);

	timer.start_timer();
	for (int i = 0; i < 20; i++)
	{
		evaluator.multiply_norelin(ct1, ct2);
	}
	cout << "Timp inmultire simpla FARA reliniarizare = " << timer.stop_timer() / 20 << endl << endl;

	timer.start_timer();
	for (int i = 0; i < 20; i++)
	{
		evaluator.multiply(ct1, ct2);
	}
	cout << "Timp inmultire simpla CU reliniarizare = " << timer.stop_timer() / 20 << endl << endl;

	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	size_t slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(10)));
	BigPoly plain_composed_poly = crtbuilder.compose(values);
	BigPoly crt_ctxt = encryptor.encrypt(plain_composed_poly);

	timer.start_timer();
	for (int i = 0; i < 20; i++)
	{
		evaluator.multiply(crt_ctxt, crt_ctxt);
	}
	cout << "Timp inmultire batch CU reliniarizare = " << timer.stop_timer() / 20 << endl << endl;

	timer.start_timer();
	for (int i = 0; i < 20; i++)
	{
		evaluator.multiply_norelin(crt_ctxt, crt_ctxt);
	}
	cout << "Timp inmultire batch FARA reliniarizare = " << timer.stop_timer() / 20 << endl << endl;
}

void test_encryption_time()
{
	MyTimer timer;

	print_example_banner("Testare timp criptare normal");

	EncryptionParameters parms;

	parms.poly_modulus() = "1x^2048 + 1";
	// parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1073153;

	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	// Create the PolyCRTBuilder
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());

	size_t slot_count = crtbuilder.get_slot_count();
	cout << "slot_count = " << slot_count << endl;

	// Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	vector<BigUInt> masca(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	srand(time(NULL));
	for (int i = 0; i < values.size(); i++)
	{
		values[i] = rand() % 256;
		masca[i] = 1;
	}
	masca[0] = 0;

	BigPoly plain_composed_poly = crtbuilder.compose(values);
	BigPoly composed_masca[4096]; // cate o masca pt. fiecare inmulire a slot-urilor
	// composed_masca[0] = crtbuilder.compose(masca);

	/*timer.start_timer();
	for (int i = 0; i < 10 && i<values.size(); i++)
	{
		composed_masca[i] = crtbuilder.compose(masca);
		masca[i] = 1;
		if (i + 1 < 4096)
		{
			masca[i + 1] = 0;
		}
	}
	cout << "Timp crtbuilder.compose = " << timer.stop_timer() / (100 * 4096) << endl << endl;*/

	// Let's do some homomorphic operations now. First we need all the encryption tools.
	// Generate keys.
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encryption tools
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key);

	Decryptor decryptor_no_relin(parms, secret_key, 2);

	// Encrypt plain_composed_poly
	cout << "Encrypting ... ";

	BigPoly encrypted_composed_poly = encryptor.encrypt(plain_composed_poly);
	BigPoly encrypted_masca[4096];

	encrypted_masca[0] = encryptor.encrypt(composed_masca[0]);

	// cout << "CRT ctxt bits size = " << encrypted_masca[0].coeff_count()*encrypted_masca[0].coeff_bit_count() << endl;

	timer.start_timer();
	for (int i = 0; i < 10; i++)
	{
		composed_masca[i] = crtbuilder.compose(masca);
		encrypted_masca[i] = encryptor.encrypt(composed_masca[i]);
	}
	cout << "Timp criptare CRT = " << masca.size() * timer.stop_timer() / 10 << endl << endl;
	// Nr. sloturi * timp_criptare_1_CRT 

	for (int i = 10; i < values.size(); i++)
	{
		encrypted_masca[i] = encrypted_masca[0];
	}

	BigPoly encoded;
	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly encrypted[4096];

	encoded = encoder.encode(values[0]);
	encrypted[0] = encryptor.encrypt(encoded);
	// cout << "Normal ctxt bits size = " << encrypted[0].coeff_count()*encrypted[0].coeff_bit_count() << endl << endl;

	// timp codificare + criptare / mesaj
	timer.start_timer();
	for (int i = 0; i < 10; i++)
	{
		encoded = encoder.encode(values[i]);
		encrypted[i] = encryptor.encrypt(encoded);
	}
	cout << "Timp codificare + criptare secventiala mesaj = " << timer.stop_timer()/10 << endl << endl;

	cout << "Inmultiri separate ...\n";

	// TIMP INMULTIRI SEPARATE
	timer.start_timer();
	for (int i = 0; i < 4096; i++)
	{
		encrypted[i] = evaluator.multiply_norelin(encrypted[0], encrypted[0]);
	}
	cout << "Timp inmultiri separate : " << timer.stop_timer() << endl << endl;

	// Let's square the encrypted_composed_poly
	// cout << "Inmultire cu batching ... ";
	// BigPoly encrypted_square = evaluator.exponentiate(encrypted_composed_poly, 2);


	// Masurare timp inmultire BATCHING
	
	timer.start_timer();

	BigPoly encrypted_square = evaluator.multiply_norelin(encrypted_composed_poly, encrypted_composed_poly);
	BigPoly shifted_result = evaluator.multiply_norelin(encrypted_square, encrypted_masca[0]);
	BigPoly result = evaluator.add(encrypted_square, encrypted_square);

	cout << "Timp inmultire batching = " << timer.stop_timer() << endl;


	return;

	cout << "done." << endl;
	cout << "Decrypting the squared polynomial ... ";
	BigPoly plain_square = decryptor_no_relin.decrypt(encrypted_square);
	cout << "done." << endl;

	// Print the squared slots
	cout << "Squared slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_square, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	return;

	// Now let's try to multiply the squares with the plaintext coefficients (3, 1, 4, 1, 5, 9, 0, 0, ..., 0).
	// First create the coefficient vector
	vector<BigUInt> plain_coeff_vector(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	plain_coeff_vector[0] = 3;
	plain_coeff_vector[1] = 1;
	plain_coeff_vector[2] = 4;
	plain_coeff_vector[3] = 1;
	plain_coeff_vector[4] = 5;
	plain_coeff_vector[5] = 9;

	// Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
	BigPoly plain_coeff_poly = crtbuilder.compose(plain_coeff_vector);

	// Print the coefficient vector
	cout << "Coefficient slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_coeff_poly, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	// Now use multiply_plain to multiply each encrypted slot with the corresponding coefficient
	cout << "Multiplying squared slots with the coefficients ... ";
	BigPoly encrypted_scaled_square = evaluator.multiply_plain(encrypted_square, plain_coeff_poly);
	cout << " done." << endl;

	cout << "Decrypting the scaled squared polynomial ... ";
	BigPoly plain_scaled_square = decryptor.decrypt(encrypted_scaled_square);
	cout << "done." << endl;

	// Print the scaled squared slots
	cout << "Scaled squared slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_scaled_square, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	// How much noise did we end up with?
	cout << "Noise in the result: " << inherent_noise(encrypted_scaled_square, parms, secret_key).significant_bit_count()
		<< "/" << inherent_noise_max(parms).significant_bit_count() << " bits" << endl;
}

void test_mult_time()
{
	EncryptionParameters parms;
	BigPoly public_key, secret_key;
	EvaluationKeys evaluation_keys;

	// parms.poly_modulus() = "1x^16384 + 1";
	// parms.coeff_modulus() = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000001";
	// parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(4096);
	// parms.plain_modulus() = 1 << (int)pow(2,14);
	// parms.decomposition_bit_count() = 32;
	parms.poly_modulus() = "1x^2048 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1 << 4;
	// cout << "PM = " << parms.plain_modulus().to_string() << endl;

	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	public_key = generator.public_key();
	secret_key = generator.secret_key();
	evaluation_keys = generator.evaluation_keys();

	int value;
	BigPoly encoded;
	BigPoly encrypted[4096];

	BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);

	BigPoly enc;

	encoded = encoder.encode(8);
	enc = encryptor.encrypt(encoded);
	enc = evaluator.multiply(enc, enc);

	Decryptor decryptor(parms, secret_key);
	encoded = decryptor.decrypt(enc);

	cout << " 0 == " << encoder.decode_int32(encoded) << endl << endl;

	return;

	srand(time(NULL));
	for (int i = 0; i < 4096; i++)
	{
		value = rand() % 256 - 128;
		encoded = encoder.encode(value);
		encrypted[i] = encryptor.encrypt(encoded);
	}

	MyTimer timer;
	timer.start_timer();

	for (int i = 0; i < 4096; i++)
	{
		encrypted[i] = evaluator.multiply_norelin(encrypted[i], encrypted[i]);
	}

	cout << "Timp inmultiri separate : " << timer.stop_timer() << endl << endl;
}

void example_basics()
{
	print_example_banner("Example: Basics");

	// In this example we demonstrate using some of the basic arithmetic operations on integers.

	// Create encryption parameters.
	EncryptionParameters parms;

	/*
	First choose the polynomial modulus. This must be a power-of-2 cyclotomic polynomial,
	i.e. a polynomial of the form "1x^(power-of-2) + 1". We recommend using polynomials of
	degree at least 1024.
	*/
	parms.poly_modulus() = "1x^2048 + 1";

	/*
	Next choose the coefficient modulus. The values we recommend to be used are:

	[ degree(poly_modulus), coeff_modulus ]
	[ 1024, "FFFFFFF00001" ],
	[ 2048, "3FFFFFFFFFFFFFFFFFF00001"],
	[ 4096, "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC0000001"],
	[ 8192, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE00000001"],
	[ 16384, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000001"].

	These can be conveniently accessed using ChooserEvaluator::default_parameter_options(),
	which returns the above list of options as an std::map, keyed by the degree of the polynomial modulus.

	The user can also relatively easily choose their custom coefficient modulus. It should be a prime number
	of the form 2^A - 2^B + 1, where A > B > degree(poly_modulus). Moreover, B should be as small as possible
	for improved efficiency in modular reduction. For security, we recommend strictly adhering to the following
	size bounds: (see Lepoint-Naehrig (2014) [https://eprint.iacr.org/2014/062])
	/------------------------------------\
	| poly_modulus | coeff_modulus bound |
	| -------------|---------------------|
	| 1x^1024 + 1  | 48 bits             |
	| 1x^2048 + 1  | 96 bits             |
	| 1x^4096 + 1  | 192 bits            |
	| 1x^8192 + 1  | 384 bits            |
	| 1x^16384 + 1 | 768 bits            |
	\------------------------------------/
	*/
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);

	/*
	Now we set the plaintext modulus. This can be any integer, even though here we take it to be a power of two.
	A larger plaintext modulus causes the noise to grow faster in homomorphic multiplication, and
	also lowers the maximum amount of noise in ciphertexts that the system can tolerate.
	On the other hand, a larger plaintext modulus typically allows for better homomorphic integer arithmetic,
	although this depends strongly on which encoder is used to encode integers into plaintext polynomials.
	*/
	parms.plain_modulus() = 1 << 20;

	/*
	The decomposition bit count affects the behavior of the relinearization (key switch) operation,
	which is typically performed after each homomorphic multiplication. A smaller decomposition
	bit count makes relinearization slower, but improves the noise growth behavior on multiplication.
	Conversely, a larger decomposition bit count makes homomorphic multiplication faster at the cost
	of increased noise growth.
	*/
	parms.decomposition_bit_count() = 32;

	/*
	We use a constant standard deviation for the error distribution. Using a larger standard
	deviation will result in larger noise growth, but in theory should make the system more secure.
	*/
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();

	/*
	For the bound on the error distribution we can also use a constant default value
	which is in fact 5 * ChooserEvaluator::default_noise_standard_deviation()
	*/
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	// Encode two integers as polynomials.
	const int value1 = 255*255*8;
	const int value2 = 1;
	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly encoded1 = encoder.encode(value1);
	BigPoly encoded2 = encoder.encode(value2);
	cout << "Encoded " << value1 << " as polynomial " << encoded1.to_string() << endl;
	cout << "Encoded " << value2 << " as polynomial " << encoded2.to_string() << endl;

	// Generate keys.
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();
	//cout << "Public Key = " << public_key.to_string() << endl;
	//cout << "Secret Key = " << secret_key.to_string() << endl;

	// Encrypt values.
	cout << "Encrypting values..." << endl;
	Encryptor encryptor(parms, public_key);
	BigPoly encrypted1 = encryptor.encrypt(encoded1);
	BigPoly encrypted2 = encryptor.encrypt(encoded2);


	// Perform arithmetic on encrypted values.
	cout << "Performing encrypted arithmetic..." << endl;
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor1(parms, secret_key);

	BigPoly encryptedproduct1 = evaluator.multiply(encrypted1, encrypted2);
	for (int i = 0; i < 1024; i++)
	{
		BigPoly decryptedproduct = decryptor1.decrypt(encryptedproduct1);
		int decodedproduct = encoder.decode_int32(decryptedproduct);

		if (decodedproduct != 1)
		{
			cout << "Log_2 max depth = " << i << endl << endl;
			return;
		}
		encryptedproduct1 = evaluator.multiply(encryptedproduct1, encryptedproduct1);

		cout << i << endl;
	}

	cout << "... Performing negation..." << endl;
	BigPoly encryptednegated1 = evaluator.negate(encrypted1);
	cout << "... Performing addition..." << endl;
	BigPoly encryptedsum = evaluator.add(encrypted1, encrypted2);
	cout << "... Performing subtraction..." << endl;
	BigPoly encrypteddiff = evaluator.sub(encrypted1, encrypted2);
	cout << "... Performing multiplication..." << endl;
	BigPoly encryptedproduct = evaluator.multiply(encrypted1, encrypted2);

	// Decrypt results.
	cout << "Decrypting results..." << endl;
	Decryptor decryptor(parms, secret_key);
	BigPoly decrypted1 = decryptor.decrypt(encrypted1);
	BigPoly decrypted2 = decryptor.decrypt(encrypted2);
	BigPoly decryptednegated1 = decryptor.decrypt(encryptednegated1);
	BigPoly decryptedsum = decryptor.decrypt(encryptedsum);
	BigPoly decrypteddiff = decryptor.decrypt(encrypteddiff);
	BigPoly decryptedproduct = decryptor.decrypt(encryptedproduct);

	// Decode results.
	int decoded1 = encoder.decode_int32(decrypted1);
	int decoded2 = encoder.decode_int32(decrypted2);
	int decodednegated1 = encoder.decode_int32(decryptednegated1);
	int decodedsum = encoder.decode_int32(decryptedsum);
	int decodeddiff = encoder.decode_int32(decrypteddiff);
	int decodedproduct = encoder.decode_int32(decryptedproduct);
	// delete evaluation_keys;

	// Display results.
	cout << value1 << " after encryption/decryption = " << decoded1 << endl;
	cout << value2 << " after encryption/decryption = " << decoded2 << endl;
	cout << "encrypted negate of " << value1 << " = " << decodednegated1 << endl;
	cout << "encrypted addition of " << value1 << " and " << value2 << " = " << decodedsum << endl;
	cout << "encrypted subtraction of " << value1 << " and " << value2 << " = " << decodeddiff << endl;
	cout << "encrypted multiplication of " << value1 << " and " << value2 << " = " << decodedproduct << endl;

	// How did the noise grow in these operations?
	int max_noise_bit_count = inherent_noise_max(parms).significant_bit_count();
	cout << "Noise in encryption of " << value1 << ": " << inherent_noise(encrypted1, parms, secret_key).significant_bit_count()
		<< "/" << max_noise_bit_count << " bits" << endl;
	cout << "Noise in encryption of " << value2 << ": " << inherent_noise(encrypted2, parms, secret_key).significant_bit_count()
		<< "/" << max_noise_bit_count << " bits" << endl;
	cout << "Noise in the sum: " << inherent_noise(encryptedsum, parms, secret_key).significant_bit_count()
		<< "/" << max_noise_bit_count << " bits" << endl;
	cout << "Noise in the product: " << inherent_noise(encryptedproduct, parms, secret_key).significant_bit_count()
		<< "/" << max_noise_bit_count << " bits" << endl;
}

void example_weighted_average()
{
	print_example_banner("Example: Weighted Average");

	// In this example we demonstrate computing a weighted average of 10 rational numbers.

	// The 10 rational numbers we use are:
	const vector<double> rational_numbers{ 3.1, 4.159, 2.65, 3.5897, 9.3, 2.3, 8.46, 2.64, 3.383, 2.795 };

	// The 10 weights are:
	const vector<double> coefficients{ 0.1, 0.05, 0.05, 0.2, 0.05, 0.3, 0.1, 0.025, 0.075, 0.05 };

	// Create encryption parameters
	EncryptionParameters parms;

	parms.poly_modulus() = "1x^1024 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(1024);
	parms.plain_modulus() = 1 << 8;

	/*
	Since we are not doing any encrypted*encrypted multiplication in this example,
	the decomposition bit count has no practical significance. We set it to the largest
	possible value to make key generation as fast as possible. However, such a large
	decomposition bit count can not be used to perform any encrypted*encrypted multiplication.
	*/
	parms.decomposition_bit_count() = parms.coeff_modulus().bit_count();

	// Set to standard values
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	// Generate keys.
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	/*
	We will need a fractional encoder for dealing with the rational numbers.
	Here we reserve 128 coefficients of the polynomial for the integral part (low-degree terms)
	and 64 coefficients for the fractional part (high-degree terms).
	*/
	BalancedFractionalEncoder encoder(parms.plain_modulus(), parms.poly_modulus(), 128, 64);

	// Create the rest of the tools
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key);

	// First we encrypt the rational numbers
	cout << "Encrypting ... ";
	vector<BigPoly> encrypted_rationals;
	for (int i = 0; i < 10; ++i)
	{
		BigPoly encoded_number = encoder.encode(rational_numbers[i]);
		encrypted_rationals.push_back(encryptor.encrypt(encoded_number));
		cout << to_string(rational_numbers[i]).substr(0, 6) + ((i < 9) ? ", " : ".\n");
	}

	// Next we encode the coefficients. There is no reason to encrypt these since they are not private data.
	cout << "Encoding ... ";
	vector<BigPoly> encoded_coefficients;
	for (int i = 0; i < 10; ++i)
	{
		encoded_coefficients.push_back(encoder.encode(coefficients[i]));
		cout << to_string(coefficients[i]).substr(0, 6) + ((i < 9) ? ", " : ".\n");
	}

	// We also need to encode 0.1. We will multiply the result by this to perform division by 10.
	BigPoly div_by_ten = encoder.encode(0.1);

	// Now compute all the products of the encrypted rational numbers with the plaintext coefficients
	cout << "Computing products ... ";
	vector<BigPoly> encrypted_products;
	for (int i = 0; i < 10; ++i)
	{
		/*
		We use Evaluator::multiply_plain(...) instead of Evaluator::multiply(...) (which would
		require also the coefficient to be encrypted). This has much better noise growth
		behavior than multiplying two encrypted numbers does.
		*/
		BigPoly enc_plain_product = evaluator.multiply_plain(encrypted_rationals[i], encoded_coefficients[i]);
		encrypted_products.push_back(enc_plain_product);
	}
	cout << "done." << endl;

	// Now we add together these products. The most convenient way to do that is
	// to use the function Evaluator::add_many(...).
	cout << "Add up all 10 ciphertexts ... ";
	BigPoly encrypted_dot_product = evaluator.add_many(encrypted_products);
	cout << " done." << endl;

	// Finally we divide by 10 to obtain the result.
	cout << "Divide by 10 ... ";
	BigPoly encrypted_result = evaluator.multiply_plain(encrypted_dot_product, div_by_ten);
	cout << "done." << endl;

	// Decrypt
	cout << "Decrypting ... ";
	BigPoly plain_result = decryptor.decrypt(encrypted_result);
	cout << "done." << endl;

	// Print the answer
	double result = encoder.decode(plain_result);
	cout << "Weighted average: " << result << endl;

	// How much noise did we end up with?
	cout << "Noise in the result: " << inherent_noise(encrypted_result, parms, secret_key).significant_bit_count()
		<< "/" << inherent_noise_max(parms).significant_bit_count() << " bits" << endl;
}

void example_parameter_selection()
{
	print_example_banner("Example: Automatic Parameter Selection");

	/*
	Here we demonstrate the automatic parameter selection tool. Suppose we want to find parameters
	that are optimized in a way that allows us to evaluate the polynomial 42x^3-27x+1. We need to know
	the size of the input data, so let's assume that x is an integer with base-3 representation of length
	at most 10.
	*/
	cout << "Finding optimized parameters for computing 42x^3-27x+1 ... ";

	ChooserEncoder chooser_encoder;
	ChooserEvaluator chooser_evaluator;

	/*
	First create a ChooserPoly representing the input data. You can think of this modeling a freshly
	encrypted cipheretext of a plaintext polynomial with length at most 10 coefficients, where the
	coefficients have absolute value at most 1.
	*/
	ChooserPoly cinput(10, 1);

	// Compute the first term
	ChooserPoly ccubed_input = chooser_evaluator.exponentiate(cinput, 3);
	ChooserPoly cterm1 = chooser_evaluator.multiply_plain(ccubed_input, chooser_encoder.encode(42));

	// Compute the second term
	ChooserPoly cterm2 = chooser_evaluator.multiply_plain(cinput, chooser_encoder.encode(27));

	// Subtract the first two terms
	ChooserPoly csum12 = chooser_evaluator.sub(cterm1, cterm2);

	// Add the constant term 1
	ChooserPoly cresult = chooser_evaluator.add_plain(csum12, chooser_encoder.encode(1));

	// To find an optimized set of parameters, we use ChooserEvaluator::select_parameters(...).
	EncryptionParameters optimal_parms;
	chooser_evaluator.select_parameters(cresult, optimal_parms);

	cout << "done." << endl;

	// Let's print these to see what was recommended
	cout << "Selected parameters:" << endl;
	cout << "{ poly_modulus: " << optimal_parms.poly_modulus().to_string() << endl;
	cout << "{ coeff_modulus: " << optimal_parms.coeff_modulus().to_string() << endl;
	cout << "{ plain_modulus: " << optimal_parms.plain_modulus().to_dec_string() << endl;
	cout << "{ decomposition_bit_count: " << optimal_parms.decomposition_bit_count() << endl;
	cout << "{ noise_standard_deviation: " << optimal_parms.noise_standard_deviation() << endl;
	cout << "{ noise_max_deviation: " << optimal_parms.noise_max_deviation() << endl;

	// Let's try to actually perform the homomorphic computation using the recommended parameters.
	// Generate keys.
	cout << "Generating keys..." << endl;
	KeyGenerator generator(optimal_parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encoding/encryption tools
	BalancedEncoder encoder(optimal_parms.plain_modulus());
	Encryptor encryptor(optimal_parms, public_key);
	Evaluator evaluator(optimal_parms, evaluation_keys);
	Decryptor decryptor(optimal_parms, secret_key);

	// Now perform the computations on real encrypted data.
	int input_value = 12345;
	BigPoly plain_input = encoder.encode(input_value);
	cout << "Encoded " << input_value << " as polynomial " << plain_input.to_string() << endl;

	cout << "Encrypting ... ";
	BigPoly input = encryptor.encrypt(plain_input);
	cout << "done." << endl;

	// Compute the first term
	cout << "Computing first term ... ";
	BigPoly cubed_input = evaluator.exponentiate(input, 3);
	BigPoly term1 = evaluator.multiply_plain(cubed_input, encoder.encode(42));
	cout << "done." << endl;

	// Compute the second term
	cout << "Computing second term ... ";
	BigPoly term2 = evaluator.multiply_plain(input, encoder.encode(27));
	cout << "done." << endl;

	// Subtract the first two terms
	cout << "Subtracting first two terms ... ";
	BigPoly sum12 = evaluator.sub(term1, term2);
	cout << "done." << endl;

	// Add the constant term 1
	cout << "Adding one ... ";
	BigPoly result = evaluator.add_plain(sum12, encoder.encode(1));
	cout << "done." << endl;

	// Decrypt and decode
	cout << "Decrypting ... ";
	BigPoly plain_result = decryptor.decrypt(result);
	cout << "done." << endl;

	// Finally print the result
	cout << "Polynomial 42x^3-27x+1 evaluated at x=12345: " << encoder.decode_int64(plain_result) << endl;

	// How much noise did we end up with?
	cout << "Noise in the result: " << inherent_noise(result, optimal_parms, secret_key).significant_bit_count()
		<< "/" << inherent_noise_max(optimal_parms).significant_bit_count() << " bits" << endl;
}

void example_batching()
{
	print_example_banner("Example: Batching using CRT");

	// Create encryption parameters
	EncryptionParameters parms;

	/*
	For PolyCRTBuilder we need to use a plain modulus congruent to 1 modulo 2*degree(poly_modulus).
	We could use the following parameters:

	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(4096);
	parms.plain_modulus() = 1 073 153;

	However, the primes suggested by ChooserEvaluator::default_parameter_options() are highly
	non-optimal for PolyCRTBuilder. The problem is that the noise in a freshly encrypted ciphertext
	will contain an additive term of the size (coeff_modulus % plain_modulus)*(largest coeff of plaintext).
	In the case of PolyCRTBuilder, the message polynomials typically have very large coefficients
	(of the size plain_modulus) and for a prime plain_modulus the remainder coeff_modulus % plain_modulus
	is typically also of the size of plain_modulus. Thus we get a term of size plain_modulus^2 to
	the noise of a freshly encrypted ciphertext! This is very bad, as normally the initial noise
	is close to size plain_modulus.

	Thus, for improved performance when using PolyCRTBuilder, we recommend the user to use their own
	custom coeff_modulus. The prime should be of the form 2^A - D, where D is as small as possible.
	The plain_modulus should be simultaneously chosen to be a prime so that coeff_modulus % plain_modulus == 1,
	and that it is congruent to 1 modulo 2*degree(poly_modulus). Finally, coeff_modulus should be bounded
	by the following strict upper bounds to ensure security:
	/------------------------------------\
	| poly_modulus | coeff_modulus bound |
	| -------------|---------------------|
	| 1x^1024 + 1  | 48 bits             |
	| 1x^2048 + 1  | 96 bits             |
	| 1x^4096 + 1  | 192 bits            |
	| 1x^8192 + 1  | 384 bits            |
	| 1x^16384 + 1 | 768 bits            |
	\------------------------------------/

	However, one issue with using such primes is that they are never NTT primes, i.e. not congruent
	to 1 modulo 2*degree(poly_modulus), and hence might not allow for certain optimizations to be
	used in polynomial arithmetic. Another issue is that the search-to-decision reduction of RLWE
	does not apply to non-NTT primes, but this is not known to result in any concrete reduction
	in the security level.

	In this example we use the prime 2^190 - 42385533 as our coefficient modulus. The user should
	try switching between this and ChooserEvaluator::default_parameter_options().at(4096) to see
	the significant difference in the noise level at the end of the computation.
	*/
	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	// parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(4096);
	parms.plain_modulus() = 1073153;

	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	// Create the PolyCRTBuilder
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());

	size_t slot_count = crtbuilder.get_slot_count();

	cout << "slot_count = " << slot_count << endl;

	// Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	vector<BigUInt> masca(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	// Set the first few entries of the values vector to be non-zero
	/*values[0] = 122;
	values[1] = 255;
	values[2] = 125;
	values[3] = 7;
	values[4] = 255;
	values[5] = 13;*/


	// int N_slots = 20;

	srand(time(NULL));
	for (int i = 0; i < values.size(); i++)
	{
		values[i] = rand() % 256;
		masca[i] = 1;
	}
	masca[0] = 0;

	// Now compose these into one polynomial using PolyCRTBuilder
	/*cout << "Plaintext slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + values[i].to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}*/
	BigPoly plain_composed_poly = crtbuilder.compose(values);
	BigPoly composed_masca[4096]; // cate o masca pt. fiecare inmulire a slot-urilor
	composed_masca[0] = crtbuilder.compose(masca);
	
	for (int i = 1; i < 4096; i++)
	{
		/*composed_masca[i] = crtbuilder.compose(masca);
		masca[i] = 1;
		if (i + 1 < 4096)
		{
			masca[i + 1] = 0;
		}*/
		composed_masca[i] = composed_masca[0];
			
	}

	// Let's do some homomorphic operations now. First we need all the encryption tools.
	// Generate keys.
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encryption tools
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key);

	Decryptor decryptor_no_relin(parms, secret_key, 2);

	// Encrypt plain_composed_poly
	cout << "Encrypting ... ";
	BigPoly encrypted_composed_poly = encryptor.encrypt(plain_composed_poly);
	BigPoly encrypted_masca[4096];
	encrypted_masca[0] = encryptor.encrypt(composed_masca[0]);
	for (int i = 1; i < 4096; i++)
	{
		encrypted_masca[i] = encrypted_masca[0];
	}
	cout << "done." << endl;


	BigPoly encoded;
	// BigPoly encrypted[4096];

	BalancedEncoder encoder(parms.plain_modulus());

	/*srand(time(NULL));
	encoded = encoder.encode(values[0]);
	encrypted[0] = encryptor.encrypt(encoded);
	for (int i = 1; i < 4096; i++)
	{
		// encoded = encoder.encode(values[i]);
		// encrypted[i] = encryptor.encrypt(encoded);
		encrypted[i] = encrypted[0];
	}


	cout << "Inmultiri separate ...\n";
	MyTimer timer;
	
	// TIMP INMULTIRI SEPARATE
	timer.start_timer();
	for (int i = 0; i < 4096; i++)
	{
		encrypted[i] = evaluator.multiply_norelin(encrypted[i], encrypted[i]);
	}
	cout << "Timp inmultiri separate : " << timer.stop_timer() << endl << endl;*/

	// Let's square the encrypted_composed_poly
	cout << "Inmultire cu batching ... ";
	
	// BigPoly encrypted_square = evaluator.exponentiate(encrypted_composed_poly, 2);


	// Masurare timp inmultire BATCHING
	MyTimer timer;
	timer.start_timer();
	BigPoly encrypted_square = evaluator.multiply_norelin(encrypted_composed_poly, encrypted_composed_poly);
	BigPoly shifted_result = evaluator.multiply_norelin(encrypted_square, encrypted_masca[0]);
	BigPoly result = evaluator.add(encrypted_square, encrypted_square);
	cout << "Timp inmultire batching = " << timer.stop_timer() << endl;

	cout << "done." << endl;
	cout << "Decrypting the squared polynomial ... ";
	BigPoly plain_square = decryptor_no_relin.decrypt(encrypted_square);
	cout << "done." << endl;

	// Print the squared slots
	cout << "Squared slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_square, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	// Now let's try to multiply the squares with the plaintext coefficients (3, 1, 4, 1, 5, 9, 0, 0, ..., 0).
	// First create the coefficient vector
	vector<BigUInt> plain_coeff_vector(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	plain_coeff_vector[0] = 3;
	plain_coeff_vector[1] = 1;
	plain_coeff_vector[2] = 4;
	plain_coeff_vector[3] = 1;
	plain_coeff_vector[4] = 5;
	plain_coeff_vector[5] = 9;

	// Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
	BigPoly plain_coeff_poly = crtbuilder.compose(plain_coeff_vector);

	// Print the coefficient vector
	cout << "Coefficient slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_coeff_poly, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	// Now use multiply_plain to multiply each encrypted slot with the corresponding coefficient
	cout << "Multiplying squared slots with the coefficients ... ";
	BigPoly encrypted_scaled_square = evaluator.multiply_plain(encrypted_square, plain_coeff_poly);
	cout << " done." << endl;

	cout << "Decrypting the scaled squared polynomial ... ";
	BigPoly plain_scaled_square = decryptor.decrypt(encrypted_scaled_square);
	cout << "done." << endl;

	// Print the scaled squared slots
	cout << "Scaled squared slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_scaled_square, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	// How much noise did we end up with?
	cout << "Noise in the result: " << inherent_noise(encrypted_scaled_square, parms, secret_key).significant_bit_count()
		<< "/" << inherent_noise_max(parms).significant_bit_count() << " bits" << endl;
}

void print_example_banner(string title)
{
	if (!title.empty())
	{
		size_t title_length = title.length();
		size_t banner_length = title_length + 2 + 2 * 10;
		string banner_top(banner_length, '*');
		string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

		cout << endl
			<< banner_top << endl
			<< banner_middle << endl
			<< banner_top << endl
			<< endl;
	}
}

void conv_parameter_selection(EncryptionParameters &optimal_parms)
{
	print_example_banner("Convolution : Automatic Parameter Selection");

	/*
	Here we demonstrate the automatic parameter selection tool. Suppose we want to find parameters
	that are optimized in a way that allows us to evaluate the polynomial 42x^3-27x+1. We need to know
	the size of the input data, so let's assume that x is an integer with base-3 representation of length
	at most 10.
	*/
	cout << "Finding optimized parameters for computing : " <<endl;
	// cout << " x^10 + x^9 + x^8 + x^7 + x^6 + x^5 + x^4 + x^3" << endl;
	cout << " Sigma(x^2*1*1*1*1*1*1*1)" << endl;

	ChooserEncoder chooser_encoder;
	ChooserEvaluator chooser_evaluator;

	/*
	First create a ChooserPoly representing the input data. You can think of this modeling a freshly
	encrypted cipheretext of a plaintext polynomial with length at most 10 coefficients, where the
	coefficients have absolute value at most 1.
	*/	
	ChooserPoly cinput(32, 1048575);
	vector<ChooserPoly> terms(8);

	// Compute the first term
	for (int i = 0; i <8; i++)
	{
		ChooserPoly x_i = chooser_evaluator.exponentiate(cinput, 2);
		// ChooserPoly cterm = chooser_evaluator.multiply_plain(x_i, chooser_encoder.encode(1));
		/*for (int i = 0; i < 7; i++)
		{
			x_i = chooser_evaluator.multiply_plain(x_i, chooser_encoder.encode(1));
		}*/
		terms[i] = x_i;
	}
	
	ChooserPoly equation = chooser_evaluator.add_many(terms);

	// To find an optimized set of parameters, we use ChooserEvaluator::select_parameters(...).
	// EncryptionParameters optimal_parms;
	chooser_evaluator.select_parameters(equation, optimal_parms);

	cout << "done." << endl;

	// Let's print these to see what was recommended
	cout << "Selected parameters:" << endl;
	cout << "{ poly_modulus: " << optimal_parms.poly_modulus().to_string() << endl;
	cout << "{ coeff_modulus: " << optimal_parms.coeff_modulus().to_string() << endl;
	cout << "{ plain_modulus: " << optimal_parms.plain_modulus().to_dec_string() << endl;
	cout << "{ decomposition_bit_count: " << optimal_parms.decomposition_bit_count() << endl;
	cout << "{ noise_standard_deviation: " << optimal_parms.noise_standard_deviation() << endl;
	cout << "{ noise_max_deviation: " << optimal_parms.noise_max_deviation() << endl;

	// Let's try to actually perform the homomorphic computation using the recommended parameters.
	// Generate keys.
	//cout << "Generating keys..." << endl;
	//KeyGenerator generator(optimal_parms);
	//generator.generate();
	//cout << "... key generation complete" << endl;
	//BigPoly public_key = generator.public_key();
	//BigPoly secret_key = generator.secret_key();
	//EvaluationKeys evaluation_keys = generator.evaluation_keys();
	//// Create the encoding/encryption tools
	//BalancedEncoder encoder(optimal_parms.plain_modulus());
	//Encryptor encryptor(optimal_parms, public_key);
	//Evaluator evaluator(optimal_parms, evaluation_keys);
	//Decryptor decryptor(optimal_parms, secret_key);
	//// Now perform the computations on real encrypted data.
	//int input_value = 12345;
	//BigPoly plain_input = encoder.encode(input_value);
	//cout << "Encoded " << input_value << " as polynomial " << plain_input.to_string() << endl;
	//cout << "Encrypting ... ";
	//BigPoly input = encryptor.encrypt(plain_input);
	//cout << "done." << endl;
	//// Compute the first term
	//cout << "Computing first term ... ";
	//BigPoly cubed_input = evaluator.exponentiate(input, 3);
	//BigPoly term1 = evaluator.multiply_plain(cubed_input, encoder.encode(42));
	//cout << "done." << endl;
	//// Compute the second term
	//cout << "Computing second term ... ";
	//BigPoly term2 = evaluator.multiply_plain(input, encoder.encode(27));
	//cout << "done." << endl;
	//// Subtract the first two terms
	//cout << "Subtracting first two terms ... ";
	//BigPoly sum12 = evaluator.sub(term1, term2);
	//cout << "done." << endl;
	//// Add the constant term 1
	//cout << "Adding one ... ";
	//BigPoly result = evaluator.add_plain(sum12, encoder.encode(1));
	//cout << "done." << endl;
	//// Decrypt and decode
	//cout << "Decrypting ... ";
	//BigPoly plain_result = decryptor.decrypt(result);
	//cout << "done." << endl;
	//// Finally print the result
	//cout << "Polynomial 42x^3-27x+1 evaluated at x=12345: " << encoder.decode_int64(plain_result) << endl;
	//// How much noise did we end up with?
	//cout << "Noise in the result: " << inherent_noise(result, optimal_parms, secret_key).significant_bit_count()
	//	<< "/" << inherent_noise_max(optimal_parms).significant_bit_count() << " bits" << endl;

};

void SEAL_save_load(bool read_write, EncryptionParameters &parms, BigPoly &public_key, 
	BigPoly &secret_key, EvaluationKeys &evaluation_keys)
{
	if (read_write == true)
	{
		/*parms.poly_modulus() = "1x^1024 + 1";
		parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
		parms.plain_modulus() = 1073153;
		parms.decomposition_bit_count() = 32;
		parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
		parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();*/
		cout << "Generating keys..." << endl;
		KeyGenerator generator(parms);
		generator.generate();
		cout << "... key generation complete" << endl;
		public_key = generator.public_key();
		secret_key = generator.secret_key();
		evaluation_keys = generator.evaluation_keys();

		ofstream out("HE_Context/parms.out", ios::out | ios::binary);
		parms.save(out);
		out.close();

		out.open("HE_Context/pk.out", ios::out | ios::binary);
		public_key.save(out);
		out.close();

		out.open("HE_Context/sk.out", ios::out | ios::binary);
		secret_key.save(out);
		out.close();

		out.open("HE_Context/ek.out", ios::out | ios::binary);
		evaluation_keys.save(out);
		out.close();
	}
	else
	{
		ifstream in("HE_Context/parms.out", ios::in | ios::binary);
		parms.load(in);
		in.close();
		in.open("HE_Context/pk.out", ios::in | ios::binary);
		public_key.load(in);
		in.close();
		in.open("HE_Context/sk.out", ios::in | ios::binary);
		secret_key.load(in);
		in.close();
		in.open("HE_Context/ek.out", ios::in | ios::binary);
		evaluation_keys.load(in);
		in.close();
	}

	BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);

	BigPoly encoded = encoder.encode(1);
	BigPoly encrypted = encryptor.encrypt(encoded);
	BigPoly product = evaluator.multiply(encrypted, encrypted);

	Decryptor decryptor(parms, secret_key);
	BigPoly decrypted = decryptor.decrypt(product);

	if (encoder.decode_int32(decrypted) != 1)
	{
		cout << "Eroare la criptare/decriptare/codificare.\n";
	}
	else
	{
		cout << "SUCCES.\n";
	}
}

void dummy_convolution(int *v1, int *v2, int l1, int l2, int *&res, int &l)
{
	cout << "FUNCTION NOT IMPLEMENTED" << endl;
	int eroare = -1;
	assert(eroare != -1);

	/*assert(l1 != 0);
	assert(l2 != 0);

	MyTimer timer;

	try
	{
		res = new int[l1 + l2];
		l = l1 + l2;
	}
	catch (std::bad_alloc ba)
	{
		cout << ba.what() << endl;
		res = nullptr;
		l = -1;
		return;
	}

	// vector in care se vor retine produsele intermediare 
	// de forma a_i * b_i si apoi se vor suma
	vector<int> coeff(l1 + l2, 0);

	for (int i = 0; i < l; i++)
	{

	}*/

	EncryptionParameters parms;
	parms.poly_modulus() = "1x^1024 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	parms.plain_modulus() = 1073153;
	// parms.plain_modulus() = 6507521;
	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encryption tools
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key);

	cout << "CRT building ..." << endl;
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	cout << "CRT finished." << endl;

	size_t slot_count = crtbuilder.get_slot_count();
	cout << "slot_count = " << slot_count << endl;

	int esantion = 1;
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(esantion)));

	BigPoly plain_composed_poly = crtbuilder.compose(values);

}

void hom_image_sharpening()
{
	// pixelii imaginii au valori intre [0, 255], sunt tonuri de gri
	cout << "Test Homomorphic Image Sharpening " << endl;

	MyTimer timer;
	EncryptionParameters parms;
	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	// parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(1024);
	parms.plain_modulus() = 1073153;
	// parms.plain_modulus() = 6507521;
	cout << "Schimpa decomposition bit count pentru a creste si mai mult viteza." << endl;
	parms.decomposition_bit_count() = 128; // modifica pentru a creste viteza de prelucrare
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);

	cout << "CRT building ..." << endl;
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	cout << "CRT finished." << endl;

	size_t slot_count = crtbuilder.get_slot_count();
	cout << "slot_count = " << slot_count << endl;

	vector<BigUInt> vecin_pixel_0(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(255)));
	cout << "crtbuilder.composing image ..." << endl;
	BigPoly image_pixels_crt = crtbuilder.compose(vecin_pixel_0);
	cout << "crt composing done." << endl;

	// creste viteza de compunere cu thread-uri, omp folosind crtbuilder.set_slot

	// pentru vecinii pixelului i 
	// vector<BigUInt> vecin_pixel_0(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(255)));
	// BigPoly vecin_pixel_0_crt = crtbuilder.compose(vecin_pixel_0);

	// vector<BigUInt> pixel(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(pixel_val)));
	// BigPoly image_pixels_crt = crtbuilder.compose(pixel);

	// filtrarea propriu_zisa a imaginii
	vector<BigPoly> encrypted_pixels(9);
	for (int i = 0; i < 9; i++)
	{
		encrypted_pixels[i] = encryptor.encrypt(image_pixels_crt); //image_pixels_crt[ i ]
	}

	int kernel[] = { 0,-1,0,-1,5,-1,0,-1,0 };
	vector<BigPoly> kernel_coeffs(9);
	for (int i = 0; i < 9; i++)
	{
		vector<BigUInt> crt_kernel(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(abs(kernel[i]))));
		kernel_coeffs[i] = crtbuilder.compose(crt_kernel);
	}

	

	timer.start_timer();
	// vector<BigPoly> produse_intermediare(9);

	BigPoly image;

#pragma omp parallel shared(image, kernel, encrypted_pixels, kernel_coeffs) \
		private(round, i, sum, index_sum, sub, index_sub)
	{vector<BigPoly> sum; int index_sum = 0;
			vector<BigPoly> sub; int index_sub = 0;

// #pragma omp for \
		shared(image, kernel, encrypted_pixels, kernel_coeffs, sum, index_sum, sub, index_sub) \
		private(i)
			for (int i = 0; i < 9; i++)
			{
				// produse_intermediare[i] = evaluator.multiply_plain(encrypted_pixels[i], kernel_coeffs[i]);

				if (kernel[i] < 0)
				{
					sub.push_back(evaluator.multiply_plain(encrypted_pixels[i], kernel_coeffs[i]));
					index_sum++;
				}
				else
				{
					sum.push_back(evaluator.multiply_plain(encrypted_pixels[i], kernel_coeffs[i]));
					index_sub++;
				}
			}

			BigPoly sumas = evaluator.add_many(sum);
			BigPoly subas = evaluator.add_many(sub);
			image = evaluator.sub(sumas, subas);
	}

	// BigPoly sharpened_image = evaluator.add_many(produse_intermediare);
	cout << "Timpul prelucrarii : " << timer.stop_timer() << endl;

	Decryptor decryptor(parms, secret_key);

	image = decryptor.decrypt(image);
	cout << "slot = " << crtbuilder.get_slot(image, rand()%1024).to_double() << " ";
	/*for (int i = 0; i < slot_count; i++)
	{
		// BigPoly p = crtbuilder.get_slot(image, i);
		cout << "slot = " << crtbuilder.get_slot(image, i).to_double()<<" ";
	}*/


	/*ofstream out("HE_Context/parms4096_batch.out", ios::out | ios::binary);
	parms.save(out);
	out.close();

	out.open("HE_Context/pk4096_batch.out", ios::out | ios::binary);
	public_key.save(out);
	out.close();

	out.open("HE_Context/sk4096_batch.out", ios::out | ios::binary);
	secret_key.save(out);
	out.close();

	out.open("HE_Context/ek4096_batch.out", ios::out | ios::binary);
	evaluation_keys.save(out);
	out.close();*/
}

void test_op(bool load)
{
	cout << "Test Substraction " << endl;

	/*EncryptionParameters parms;
	parms.poly_modulus() = "1x^2048 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1 << 8;
	parms.decomposition_bit_count() = 32; 
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;

	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);

	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly val1 = encoder.encode(10);
	BigPoly val2 = encoder.encode(3);

	BigPoly x = encryptor.encrypt(val1);
	BigPoly y = encryptor.encrypt(val2);;

	try
	{
		BigPoly res = evaluator.multiply(x, y);
		Decryptor decryptor(parms, secret_key);
		BigPoly decrypted = decryptor.decrypt(res);

		cout << "res = " << encoder.decode_int32(res) << endl << endl;
	}
	catch (...)
	{
		cout << "This is PROGRAMMING." << endl;
	}*/
	

	EncryptionParameters parms;
	BigPoly public_key;
	BigPoly secret_key;
	EvaluationKeys evaluation_keys;

	if (load == true)
	{

		ifstream in("HE_Context/parms.out", ios::in | ios::binary);
		parms.load(in);
		in.close();
		in.open("HE_Context/pk.out", ios::in | ios::binary);
		public_key.load(in);
		in.close();
		in.open("HE_Context/sk.out", ios::in | ios::binary);
		secret_key.load(in);
		in.close();
		in.open("HE_Context/ek.out", ios::in | ios::binary);
		evaluation_keys.load(in);
		in.close();
	}
	else
	{

		parms.poly_modulus() = "1x^2048 + 1";
		parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
		parms.plain_modulus() = 1 << 8;
		parms.decomposition_bit_count() = 32;
		parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
		parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

		cout << "Generating keys..." << endl;
		KeyGenerator generator(parms);
		generator.generate();
		cout << "... key generation complete" << endl;
		public_key = generator.public_key();
		secret_key = generator.secret_key();
		evaluation_keys = generator.evaluation_keys();

		ofstream out("HE_Context/parms2048.out", ios::out | ios::binary);
		parms.save(out);
		out.close();
		out.open("HE_Context/pk2048.out", ios::out | ios::binary);
		public_key.save(out);
		out.close();
		out.open("HE_Context/sk2048.out", ios::out | ios::binary);
		secret_key.save(out);
		out.close();
		out.open("HE_Context/ek2048.out", ios::out | ios::binary);
		evaluation_keys.save(out);
		out.close();
	}

	const int value1 = 7;
	const int value2 = 7;
	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly encoded1 = encoder.encode(value1);
	BigPoly encoded2 = encoder.encode(value2);

	Encryptor encryptor(parms, public_key);
	BigPoly encrypted1 = encryptor.encrypt(encoded1);
	BigPoly encrypted2 = encryptor.encrypt(encoded2);

	// Perform arithmetic on encrypted values.
	cout << "Performing encrypted arithmetic..." << endl;
	Evaluator evaluator(parms, evaluation_keys);

	MyTimer timer;
	timer.start_timer();
	BigPoly result = evaluator.multiply_plain(encrypted1, encoded2);
	double time = timer.stop_timer();
	cout << "Timp = " << time << endl;

	Decryptor decryptor(parms, secret_key);
	BigPoly decrypted = decryptor.decrypt(result);
	cout << "Result = " << encoder.decode_int32(decrypted) << endl;

	/*cout << "... Performing negation..." << endl;
	BigPoly encryptednegated1 = evaluator.negate(encrypted1);
	cout << "... Performing addition..." << endl;
	BigPoly encryptedsum = evaluator.add(encrypted1, encrypted2);
	cout << "... Performing subtraction..." << endl;
	BigPoly encrypteddiff = evaluator.sub(encrypted1, encrypted1);
	cout << "... Performing multiplication..." << endl;
	BigPoly encryptedproduct = evaluator.multiply(encrypted1, encrypted2);*/

	/*BigPoly zero = encoder.encode(0);
	cout << "Encoded zero = " << zero.to_string() << endl;
	BigPoly encrypted_zero = encryptor.encrypt(zero);
	BigPoly encrypteddiff = evaluator.sub(encrypted1, encrypted2);
	Decryptor decryptor(parms, secret_key);
	BigPoly decrypted_zero = decryptor.decrypt(encrypted_zero);
	cout << "Zero = " << decrypted_zero.to_string() << endl;*/


	/*BigPoly decrypted1 = decryptor.decrypt(encrypted1);
	BigPoly decrypted2 = decryptor.decrypt(encrypted2);
	BigPoly decryptednegated1 = decryptor.decrypt(encryptednegated1);
	BigPoly decryptedsum = decryptor.decrypt(encryptedsum);
	BigPoly decrypteddiff = decryptor.decrypt(encrypteddiff);
	BigPoly decryptedproduct = decryptor.decrypt(encryptedproduct);

	// Decode results.
	int decoded1 = encoder.decode_int32(decrypted1);
	int decoded2 = encoder.decode_int32(decrypted2);
	int decodednegated1 = encoder.decode_int32(decryptednegated1);
	int decodedsum = encoder.decode_int32(decryptedsum);
	int decodeddiff = encoder.decode_int32(decrypteddiff);
	int decodedproduct = encoder.decode_int32(decryptedproduct);

	// Display results.
	cout << value1 << " after encryption/decryption = " << decoded1 << endl;
	cout << value2 << " after encryption/decryption = " << decoded2 << endl;
	cout << "encrypted negate of " << value1 << " = " << decodednegated1 << endl;
	cout << "encrypted addition of " << value1 << " and " << value2 << " = " << decodedsum << endl;
	cout << "encrypted subtraction of " << value1 << " and " << value2 << " = " << decodeddiff << endl;
	cout << "encrypted multiplication of " << value1 << " and " << value2 << " = " << decodedproduct << endl;*/

}

void hom_k_means()
{


}

void test_HE_image()
{
	MyTimer timer;
	double elapsed_time = 0.0;

	EncryptionParameters parms;
	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	parms.plain_modulus() = 1073153;
	cout << "Schimpa decomposition bit count pentru a creste si mai mult viteza." << endl;
	parms.decomposition_bit_count() = 128; 
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	BigPoly public_key;
	BigPoly secret_key;
	EvaluationKeys evaluation_keys;

	generate_parameters(parms, public_key, secret_key, evaluation_keys);

	cout << "Generare Parametrii cu succes" << endl;
	int N = 3;
	cout << "Se creeaza obiectul he_image ..." << endl;
	HE_Image he_image(parms, N);
	cout << "S-a creat obiectul he_image." << endl;

	// test_crt_builder(he_image.get_enc_params(), he_image.get_crt_builder());

	int **result = nullptr;
	int **mat_pixels = nullptr;
	mat_pixels = new int*[512];
	result = new int*[512];
	for (int i = 0; i < 512; i++)
	{
		mat_pixels[i] = new int[512];
		for (int j = 0; j < 512; j++)
		{
			mat_pixels[i][j] = 255;
		}

		result[i] = new int[512];
		memset(result[i], 0, sizeof(int) * 512);
	}

	vector<vector<BigPoly> > enc_kernels;
	int slot_count = 0;
	cout << "Se cripteaza imaginea ..." << endl;
	he_image.encrypt_for_filtering(mat_pixels, 512, enc_kernels, slot_count, public_key);
	cout << "Imagine criptata cu SUCCES." << endl;

	int *kernel = new int[9];
	kernel[0] = kernel[2] = kernel[6] = kernel[8] = 0;
	kernel[1] = kernel[3] = kernel[5] = kernel[7] = -1;
	kernel[4] = 5;

	vector<BigPoly> encoded_filter;
	cout << "Se codifica filtrul ..." << endl;
	he_image.encode_filter(kernel, N, encoded_filter, slot_count);
	cout << "Filtrul codificat cu SUCCES." << endl;

	vector<BigPoly> filtered_image;
	cout << "Se filtreaza homomorfic imaginea ..." << endl;

	timer.start_timer();
	he_image.hom_filtering(enc_kernels, encoded_filter, kernel, filtered_image, evaluation_keys, secret_key);
	elapsed_time = timer.stop_timer();

	cout << "S-a terminat de filtrat homomorfic imaginea." << endl;
	cout << "Timp filtrare homomorfica = " << elapsed_time << endl;

	assert(filtered_image.size() == enc_kernels.size());

	cout << "Se decripteaza imaginea dupa filtrare." << endl;
	int *dec_image = nullptr;
	
	timer.start_timer();
	he_image.omp_decrypt_after_filtering(dec_image, filtered_image, slot_count, secret_key);
	elapsed_time = timer.stop_timer();

	cout << "S-a decriptat imaginea." << endl << endl;
	cout << "Timp decriptare paralelizata = " << elapsed_time << endl << endl;

	bool ok = true;
	for (int i = 0; i < 512; i++)
	{
		for (int j = 0; j < 512; j++)
		{
			if (mat_pixels[i][j] != dec_image[i*512+j] )
			{
				cout << mat_pixels[i][j] << " != " << dec_image[i * 512 + j] << endl;
				cout << " i = " << i << ", j = " << j << endl;
				cout << "Valori incorecte.\n";
				ok = false;
				i = 512;
				break;
			}
		}
	}

	if (ok == true)
	{
		cout << "BIG SUCCES hE_IMAGE MERGE !!!" << endl;
	}
	else
	{
		cout << "ESEC : erori la filtrare." << endl;
	}


	vector<string> files(5);
	files[0] = "HE_Context/parms1024.out";
	files[1] = "HE_Context/pk1024.out";
	files[2] = "HE_Context/sk1024.out";
	files[3] = "HE_Context/ek1024.out";

	save_parameters(files, parms, public_key, secret_key, evaluation_keys);

	// cleanup
	for (int i = 0; i < 512; i++)
	{
		delete[] mat_pixels[i];
		delete[] result[i];
	}
	delete[] mat_pixels;
	delete[] result;

	if (dec_image != nullptr)
	{
		delete[] dec_image;
	}

	delete[] kernel;
}

void test_crt_builder(const EncryptionParameters parms, PolyCRTBuilder &crtbuilder)
{
	// pixelii imaginii au valori intre [0, 255], sunt tonuri de gri
	cout << "Test Homomorphic Image Sharpening " << endl;

	MyTimer timer;
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);

	size_t slot_count = crtbuilder.get_slot_count();
	cout << "slot_count = " << slot_count << endl;

	vector<BigUInt> vecin_pixel_0(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(255)));
	cout << "crtbuilder.composing image ..." << endl;
	BigPoly image_pixels_crt = crtbuilder.compose(vecin_pixel_0);
	cout << "crt composing done." << endl;

	vector<BigPoly> encrypted_pixels(9);
	for (int i = 0; i < 9; i++)
	{
		encrypted_pixels[i] = encryptor.encrypt(image_pixels_crt); //image_pixels_crt[ i ]
	}

	int kernel[] = { 0,-1,0,-1,5,-1,0,-1,0 };
	vector<BigPoly> kernel_coeffs(9);
	for (int i = 0; i < 9; i++)
	{
		vector<BigUInt> crt_kernel(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(abs(kernel[i]))));
		kernel_coeffs[i] = crtbuilder.compose(crt_kernel);
	}



	timer.start_timer();

	BigPoly image;

#pragma omp parallel shared(image, kernel, encrypted_pixels, kernel_coeffs) \
		private(round, i, sum, index_sum, sub, index_sub)
	{
		vector<BigPoly> sum; int index_sum = 0;
		vector<BigPoly> sub; int index_sub = 0;

		// #pragma omp for \
				shared(image, kernel, encrypted_pixels, kernel_coeffs, sum, index_sum, sub, index_sub) \
		private(i)
		for (int i = 0; i < 9; i++)
		{
			// produse_intermediare[i] = evaluator.multiply_plain(encrypted_pixels[i], kernel_coeffs[i]);

			if (kernel[i] < 0)
			{
				sub.push_back(evaluator.multiply_plain(encrypted_pixels[i], kernel_coeffs[i]));
				index_sum++;
			}
			else
			{
				sum.push_back(evaluator.multiply_plain(encrypted_pixels[i], kernel_coeffs[i]));
				index_sub++;
			}
		}

		BigPoly sumas = evaluator.add_many(sum);
		BigPoly subas = evaluator.add_many(sub);
		image = evaluator.sub(sumas, subas);
#pragma omp for
		for (int round = 0; round < 8; round++)
		{

		}
	}

	cout << "Timpul prelucrarii : " << timer.stop_timer() << endl;

	Decryptor decryptor(parms, secret_key);

	image = decryptor.decrypt(image);
	cout << "slot = " << crtbuilder.get_slot(image, rand() % 1024).to_double() << " ";
}

void test_field()
{
	print_example_banner("Example: Batching using CRT");

	// Create encryption parameters
	EncryptionParameters parms;

	/*
	For PolyCRTBuilder we need to use a plain modulus congruent to 1 modulo 2*degree(poly_modulus).
	We could use the following parameters:

	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(4096);
	parms.plain_modulus() = 1073153;

	However, the primes suggested by ChooserEvaluator::default_parameter_options() are highly
	non-optimal for PolyCRTBuilder. The problem is that the noise in a freshly encrypted ciphertext
	will contain an additive term of the size (coeff_modulus % plain_modulus)*(largest coeff of plaintext).
	In the case of PolyCRTBuilder, the message polynomials typically have very large coefficients
	(of the size plain_modulus) and for a prime plain_modulus the remainder coeff_modulus % plain_modulus
	is typically also of the size of plain_modulus. Thus we get a term of size plain_modulus^2 to
	the noise of a freshly encrypted ciphertext! This is very bad, as normally the initial noise
	is close to size plain_modulus.

	Thus, for improved performance when using PolyCRTBuilder, we recommend the user to use their own
	custom coeff_modulus. The prime should be of the form 2^A - D, where D is as small as possible.
	The plain_modulus should be simultaneously chosen to be a prime so that coeff_modulus % plain_modulus == 1,
	and that it is congruent to 1 modulo 2*degree(poly_modulus). Finally, coeff_modulus should be bounded
	by the following strict upper bounds to ensure security:
	/------------------------------------\
	| poly_modulus | coeff_modulus bound |
	| -------------|---------------------|
	| 1x^1024 + 1  | 48 bits             |
	| 1x^2048 + 1  | 96 bits             |
	| 1x^4096 + 1  | 192 bits            |
	| 1x^8192 + 1  | 384 bits            |
	| 1x^16384 + 1 | 768 bits            |
	\------------------------------------/

	However, one issue with using such primes is that they are never NTT primes, i.e. not congruent
	to 1 modulo 2*degree(poly_modulus), and hence might not allow for certain optimizations to be
	used in polynomial arithmetic. Another issue is that the search-to-decision reduction of RLWE
	does not apply to non-NTT primes, but this is not known to result in any concrete reduction
	in the security level.

	In this example we use the prime 2^190 - 42385533 as our coefficient modulus. The user should
	try switching between this and ChooserEvaluator::default_parameter_options().at(4096) to see
	the significant difference in the noise level at the end of the computation.
	*/
	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	//parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(4096);
	parms.plain_modulus() = 1073153;

	parms.decomposition_bit_count() = 32;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	// Create the PolyCRTBuilder
	PolyCRTBuilder crtbuilder(parms.plain_modulus(), parms.poly_modulus());
	size_t slot_count = crtbuilder.get_slot_count();

	// Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	// Set the first few entries of the values vector to be non-zero
	values[0] = 15;
	values[1] = 36;
	values[2] = 16;
	values[3] = 35;
	values[4] = 40;
	values[5] = 13;

	// Now compose these into one polynomial using PolyCRTBuilder
	cout << "Plaintext slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + values[i].to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}
	BigPoly plain_composed_poly = crtbuilder.compose(values);

	// Let's do some homomorphic operations now. First we need all the encryption tools.
	// Generate keys.
	cout << "Generating keys..." << endl;
	KeyGenerator generator(parms);
	generator.generate();
	cout << "... key generation complete" << endl;
	BigPoly public_key = generator.public_key();
	BigPoly secret_key = generator.secret_key();
	EvaluationKeys evaluation_keys = generator.evaluation_keys();

	// Create the encryption tools
	Encryptor encryptor(parms, public_key);
	Evaluator evaluator(parms, evaluation_keys);
	Decryptor decryptor(parms, secret_key);

	// Encrypt plain_composed_poly
	cout << "Encrypting ... ";
	BigPoly encrypted_composed_poly = encryptor.encrypt(plain_composed_poly);
	cout << "done." << endl;

	// Let's square the encrypted_composed_poly
	cout << "Squaring the encrypted polynomial ... ";
	BigPoly encrypted_square = evaluator.exponentiate(encrypted_composed_poly, 2);
	cout << "done." << endl;
	cout << "Decrypting the squared polynomial ... ";
	BigPoly plain_square = decryptor.decrypt(encrypted_square);
	cout << "done." << endl;

	// Print the squared slots
	cout << "Squared slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_square, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	// Now let's try to multiply the squares with the plaintext coefficients (3, 1, 4, 1, 5, 9, 0, 0, ..., 0).
	// First create the coefficient vector
	vector<BigUInt> plain_coeff_vector(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	plain_coeff_vector[0] = 643892;
	plain_coeff_vector[1] = 643892;
	plain_coeff_vector[2] = 643892;
	plain_coeff_vector[3] = 643892;
	plain_coeff_vector[4] = 643892;
	plain_coeff_vector[5] = 643892;

	// Use PolyCRTBuilder to compose plain_coeff_vector into a polynomial
	BigPoly plain_coeff_poly = crtbuilder.compose(plain_coeff_vector);

	// Print the coefficient vector
	cout << "Coefficient slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_coeff_poly, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	// Now use multiply_plain to multiply each encrypted slot with the corresponding coefficient
	cout << "Multiplying squared slots with the coefficients ... ";
	BigPoly encrypted_scaled_square = evaluator.multiply_plain(encrypted_square, plain_coeff_poly);
	cout << " done." << endl;

	cout << "Decrypting the scaled squared polynomial ... ";
	BigPoly plain_scaled_square = decryptor.decrypt(encrypted_scaled_square);
	cout << "done." << endl;

	// Print the scaled squared slots
	cout << "Scaled squared slot contents (slot, value): ";
	for (size_t i = 0; i < 6; ++i)
	{
		string to_write = "(" + to_string(i) + ", " + crtbuilder.get_slot(plain_scaled_square, i).to_dec_string() + ")";
		to_write += (i != 5) ? ", " : "\n";
		cout << to_write;
	}

	// How much noise did we end up with?
	cout << "Noise in the result: " << inherent_noise(encrypted_scaled_square, parms, secret_key).significant_bit_count()
		<< "/" << inherent_noise_max(parms).significant_bit_count() << " bits" << endl;

}

