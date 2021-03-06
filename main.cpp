#include <iostream>
#include <time.h>
#include <fstream>
#include "HE_Signal.h"
#include <assert.h>
#include "MyTimer.h"
#include "basic_examples.h"

Evaluator* eval;
EncryptionParameters* parms;
BigPoly* public_key;
BigPoly* secret_key;
BigPoly* ctxt_of_1;                  // encryption of 1 (constant)
int		t_bits;

void example_signal_processing()
{
	HE_Signal signal2;
	// cout << "\n========================================\n";
	// HE_Signal signal2;

	int N = 10;
	vector<int> s1(N);
	vector<int> s2(N);

	srand(time(NULL));
	for (int i = 0; i < N; i++)
	{
		s1[i] = rand() % 256 - 128;
		s2[i] = rand() % 256 - 128;
	}

	vector<BigPoly> enc_s1;
	vector<BigPoly> enc_s2;

	signal2.encrypt_signal(s1, enc_s1);
	signal2.encrypt_signal(s2, enc_s2);

	vector<int> dec_s1;
	vector<int> dec_s2;
	signal2.decrypt_signal(dec_s1, enc_s1);
	signal2.decrypt_signal(dec_s2, enc_s2);

	for (int i = 0; i < dec_s1.size(); i++)
	{
		if (dec_s1[i] != s1[i])
		{
			cout << "Eroare la s1\n";
			break;
		}

		if (dec_s2[i] != s2[i])
		{
			cout << "Eroare la s2\n";
			break;
		}
	}

	vector<int> s_mult;
	vector<BigPoly> enc_s_mult;

	mult_plain_signals(s1, s2, s_mult);

	cout << "s1 = [ ";
	for (int i = 0; i < s1.size(); i++)
	{
		cout << s1[i] << " ";
	}
	cout << "]"<< endl;
	cout << "s2 = [ ";
	for (int i = 0; i < s2.size(); i++)
	{
		cout << s2[i] << " ";
	}
	cout << "]" << endl << endl;
	cout << "s_mult = [ ";
	for (int i = 0; i < s_mult.size(); i++)
	{
		cout << s_mult[i] << " ";
	}
	cout << "]" << endl;

	MyTimer timer;
	timer.start_timer();
	signal2.mult_enc_signals(enc_s1, enc_s2, enc_s_mult);
	cout << "\nTimp convolutie homomorfica : " << timer.stop_timer() << endl << endl;

	vector<int> dec_s_mult;
	signal2.decrypt_no_relin(dec_s_mult, enc_s_mult);
	cout << "DECs_m = [ ";
	for (int i = 0; i < dec_s_mult.size(); i++)
	{
		if (s_mult[i] != dec_s_mult[i] )
		{
			cout << "\n!!! Valorile convolutiei in clar difera de rezultatele convolutiei homomorfice.\n";
			break;
		}
		cout << (int)dec_s_mult[i] << " ";
	}
	cout << " ]\n";

	cout << "\nFinal prelucrare semnale\n\n";

}

void example();

void codificare_semnal_ca_polinom();


/*
19701002217493787572 859 706 405 990 105 231 706 515 944 406 718 582 863 
759 472 395 429 055 407 119 738 991 784 478 887 845 639 079 714 418 065 409
*/

int main()
{
<<<<<<< HEAD
=======
	test_field();

	// test_HE_image();

	// return 0;

>>>>>>> 7c570c69db37f1316133fa76890ee49d07951436
	EncryptionParameters parms;

	/*parms.poly_modulus() = "1x^1024 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	parms.plain_modulus() = 1073153;
	cout << "Schimpa decomposition bit count pentru a creste si mai mult viteza." << endl;
	parms.decomposition_bit_count() = 32; // modifica pentru a creste viteza de prelucrare
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();
	BigPoly public_key;
	BigPoly secret_key;
	EvaluationKeys evaluation_keys;
	generate_parameters(parms, public_key, secret_key, evaluation_keys);
	vector<string> files(5);
	files[0] = "HE_Context/parms1024.out";
	files[1] = "HE_Context/parms1024.out";
	files[2] = "HE_Context/parms1024.out";
	files[3] = "HE_Context/parms1024.out";*/

<<<<<<< HEAD
	parms.poly_modulus() = "1x^8192 + 1";
	BigUInt two_sixty("FFFFFFE00000001"); // 2 ^ 60
	BigUInt res = two_sixty * two_sixty * two_sixty * two_sixty * two_sixty * two_sixty;
	res = res * BigUInt("800000") - BigUInt("200000000") + BigUInt("1");
	parms.coeff_modulus() = "7FFFFFA000001E2FFFFAE200007F877FF90C40002FB49FFF90C400007F877FFFAE2000001E2FFFFFF9FFFFFE00800001";
	parms.plain_modulus() = 1099512004609;
	parms.decomposition_bit_count() = 512;

	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();

	generate_parameters(parms, public_key, secret_key, evaluation_keys);

	vector<string> files(4);
	files[0] = "RES\parms8192.out";
	files[1] = "RES\pk8192.out";
	files[2] = "RES\sk8192.out";
	files[3] = "RES\ek8192.out";
	save_parameters(files, parms, public_key, secret_key, evaluation_keys);

	cout << "Program incheiat cu SUCCES." << endl;
	return 0;

/************************************************************************************/
	
	

=======
	
>>>>>>> 7c570c69db37f1316133fa76890ee49d07951436
	conv_parameter_selection(parms);

	cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	string coeff = parms.coeff_modulus().to_string();
	int count = 0;

	for (int i = 0; i < coeff.size(); i++)
	{
		if (coeff[i] == 'F')
		{
			count++;
		}
	}

	cout << endl << "cout_F = " << count << endl << endl;

	ofstream out("gen_param.txt");
	out << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;
	out.close();

	// SEAL_save_load(true, parms, public_key, secret_key, evaluation_keys);


	// seteaza parametrii a.i. BATCHING-UL SA FIE POSIBIL
	// test_real_conv(parms, public_key, secret_key, evaluation_keys);

	//cout << "Encryption parameters specify " << parms.poly_modulus().significant_coeff_count() << " coefficients with "
		//<< parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	// example_parameter_selection();

	// example_basics();

	// SEAL_eval_max_depth(parms, public_key, secret_key, evaluation_keys);

	// batch_low_param(parms, public_key, secret_key, evaluation_keys);

	test_homomorphic_conv();

	// test_reliniarize_after_many_mults();

	// test_mix_mult();

	// test_encryption_time();

	// codificare_semnal_ca_polinom();

	// FFT fft;
	// fft.test_fft();

	// example_signal_processing();

	// example();

	// example_basics();

	// example_batching(); // batching-ul nu suporta nr. negative

	// testeaza_descomp_polinoame();

	/*srand(time(NULL));
	int semnal1 = 0;
	int coeff = 0;
	int doi_la_pow = 1;
	for (int i = 0; i < 4; i++)
	{
		coeff = rand() % 7; // - 128;
		cout << coeff << " ";
		semnal1 += doi_la_pow*coeff;
		doi_la_pow *= 3;
	}
	cout << "semnal1 = " << semnal1 << endl;

	int v[4];
	doi_la_pow = pow(3, 3);
	for (int i = 3; i >-1; i--)
	{
		v[i] = semnal1 / doi_la_pow;
		semnal1 = semnal1 % doi_la_pow;
		doi_la_pow /= 3;
	}
	for (int i = 0; i < 4; i++)
	{
		cout << v[i] << " ";
	}
	cout << endl;*/

	return 0;
}     

void example()
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

	/*ifstream in;
	in.open("parms2048.out");
	parms.load(in);
	in.close();

	in.open("sk2048.out");
	secret_key.load(in);
	in.close();

	in.open("pk2048.out");
	public_key.load(in);
	in.close();

	in.open("ek2048.out");
	evaluation_keys.load(in);
	in.close();*/

	const int value1 = 2;
	const int value2 = 2;
	BalancedEncoder encoder(parms.plain_modulus());
	BigPoly encoded1 = encoder.encode(value1);
	BigPoly encoded2 = encoder.encode(value2);

	cout << "Codificare cu succes.\n";

	Encryptor encryptor(parms, public_key);
	BigPoly encrypted1 = encryptor.encrypt(encoded1);
	BigPoly encrypted2 = encryptor.encrypt(encoded2);

	cout << "Criptare cu succes\n";
	Evaluator evaluator(parms, evaluation_keys);
	cout << "... Performing multiplication..." << endl;

	vector<BigPoly> copies(100);

	// "Mini convolutie fara reliniarizare dupa inmultire"
	MyTimer timer;

	timer.start_timer();
	BigPoly encryptedproduct = evaluator.multiply_norelin(encrypted1, encrypted2);
	encryptedproduct = evaluator.multiply_norelin(encrypted1, encrypted2);
	encryptedproduct = evaluator.multiply_norelin(encrypted1, encrypted2);
	encryptedproduct = evaluator.multiply_norelin(encrypted1, encrypted2);
	encryptedproduct = evaluator.multiply_norelin(encrypted1, encrypted2);
	encryptedproduct = evaluator.multiply_norelin(encrypted1, encrypted2);
	cout << "*** TIMP 6 (SASE) INMULTIRI : " << timer.stop_timer() << endl;

	for (int i = 0; i < 100; i++)
	{
		copies[i] = encryptedproduct;
	}
	BigPoly conv = evaluator.add_many(copies);
	// cout << "timp conv NO RELIN = " << timer.stop_timer() << endl;

	timer.start_timer();
	encryptedproduct = evaluator.multiply(encrypted1, encrypted2);
	for (int i = 0; i < 100; i++)
	{
		copies[i] = encryptedproduct;
	}

	BigPoly conv_relin = evaluator.add_many(copies);
	cout << "timp conv CU RELIN = " << timer.stop_timer() << endl;

	try
	{
		Decryptor decryptor_relin(parms, secret_key);
		BigPoly decoded_relin = decryptor_relin.decrypt(conv_relin);
		int decodedproduct_relin = encoder.decode_int32(decoded_relin);
		cout << "RELIN = " << decodedproduct_relin << endl;
	}
	catch (std::invalid_argument)
	{
		cout << "Invalid argument exception thrown\n";
	}
	

	Decryptor decryptor(parms, secret_key, 2);
	BigPoly decoded = decryptor.decrypt(conv);

	

	int decodedproduct = encoder.decode_int32(decoded);
	
	// int decodedsum = encoder.decode_int32(decryptedsum);
	// int s = encoder.decode_int32(sum);

	cout << "FARA RELIN " << decodedproduct << endl;
	
	// cout << "encrypted add many of " << value1 << " and " << value2 << " = " << s << endl;

	/*ofstream out;
	out.open("parms2048.out");
	parms.save(out);
	out.close();

	out.open("pk2048.out");
	public_key.save(out);
	out.close();

	out.open("sk2048.out");
	secret_key.save(out);
	out.close();

	out.open("ek2048.out");
	evaluation_keys.save(out);
	out.close();*/

	cout << "Final test SEAL.\n";
}

void codificare_semnal_ca_polinom()
{
	EncryptionParameters parms;
	BigPoly public_key, secret_key;
	EvaluationKeys evaluation_keys;
	/*parms.poly_modulus() = "1x^2048 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1 << 8;*/
	parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	parms.plain_modulus() = 1073153;
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

	srand(time(NULL));
	int semnal1 = 0;
	int semnal2 = 0;
	int coeff = 0;
	int doi_la_pow = 1;
	// cout << "semnal = [ ";
	for (int i = 0; i < 10; i++)
	{	
		coeff = rand() % 256 - 128;
		// cout << coeff << " ";
		semnal1 += doi_la_pow*coeff;
		coeff = rand() % 256 - 128;
		semnal2 += doi_la_pow*coeff;
		doi_la_pow *= 2;
	}
	// cout << " ] " << endl;
	cout << "semnal1 = " << semnal1 << endl;
	cout << "semnal2 = " << semnal2 << endl;

	/*doi_la_pow = pow(2, 9);
	for (int i = 0; i < 10; i++)
	{
		cout << semnal1 / doi_la_pow << " ";
		semnal1 = semnal1 % doi_la_pow;
		doi_la_pow /= 2;
	}*/

	BalancedEncoder encoder(parms.plain_modulus(), 257);
	BigPoly encoded_signal1 = encoder.encode(semnal1);
	BigPoly encoded_signal2 = encoder.encode(semnal2);
	cout << "Codificare cu succes.\n";

	Encryptor encryptor(parms, public_key);
	BigPoly encrypted_signal1 = encryptor.encrypt(encoded_signal1);
	BigPoly encrypted_signal2 = encryptor.encrypt(encoded_signal2);
	cout << "Criptare cu succes\n";

	Decryptor decryptor(parms, secret_key);
	BigPoly decrypted_signal1 = decryptor.decrypt(encrypted_signal1);
	int semnal_decriptat1 = encoder.decode_int32(decrypted_signal1);
	cout << "semnal_decriptat_1 = " << semnal_decriptat1 << endl;
	BigPoly decrypted_signal2 = decryptor.decrypt(encrypted_signal2);
	int semnal_decriptat2 = encoder.decode_int32(decrypted_signal2);
	cout << "semnal_decriptat_2 = " << semnal_decriptat2 << endl;

	Evaluator evaluator(parms, evaluation_keys);
	BigPoly encryptedproduct = evaluator.multiply(encrypted_signal1, encrypted_signal2);
	BigPoly decryptedproduct = decryptor.decrypt(encryptedproduct);
	int rezultat = encoder.decode_int32(decryptedproduct);
	cout << "Rezultat_Hom = " << rezultat << endl;
	cout << "Rezultat_Clar = " << semnal1*semnal2 << endl;

	doi_la_pow = pow(2, 9);
	for (int i = 0; i < 10; i++)
	{
		cout << semnal_decriptat1/doi_la_pow << " ";
		semnal_decriptat1 = semnal_decriptat1 % doi_la_pow;
		doi_la_pow /= 2;
	}

}

