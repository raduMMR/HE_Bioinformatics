#include "HE_Signal.h"
#include <fstream>

// !!! corectie bug operator de egalitate BigPoly

HE_Signal::HE_Signal(const char* poly_modulus, int plain_modulus,
	int decomposition_bit_count, const char *coeff_modulus)
{
	cout << "Generare chei ..." << endl;

	/*parms.poly_modulus() = "1x^2048 + 1";
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	parms.plain_modulus() = 1 << 8;
	parms.decomposition_bit_count() = 32;*/
	/*parms.poly_modulus() = "1x^4096 + 1";
	parms.coeff_modulus() = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD793F83";
	parms.plain_modulus() = 1073153;
	parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	parms.noise_max_deviation() = ChooserEvaluator::default_noise_max_deviation();*/

	parms.poly_modulus() = poly_modulus;
	if (strlen(coeff_modulus) == 0)
		parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	else
		parms.coeff_modulus() = coeff_modulus;
	parms.plain_modulus() = plain_modulus;
	parms.decomposition_bit_count() = decomposition_bit_count;

	KeyGenerator generator(parms);
	generator.generate();
	public_key = new BigPoly(generator.public_key());
	secret_key = new BigPoly(generator.secret_key());
	evaluation_keys = new EvaluationKeys(generator.evaluation_keys());

	/*ifstream in("HE_Context/parms.out", ios::in | ios::binary);
	parms.load(in);
	in.close();
	in.open("HE_Context/pk.out", ios::in | ios::binary);
	public_key->load(in);
	in.close();
	in.open("HE_Context/sk.out", ios::in | ios::binary);
	secret_key->load(in);
	in.close();
	in.open("HE_Context/ek.out", ios::in | ios::binary);
	evaluation_keys->load(in);
	in.close();*/

	/*BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, *public_key);
	Decryptor decryptor(parms, *secret_key);

	BigPoly encoded1 = encoder.encode(1);
	BigPoly encrypted1 = encryptor.encrypt(encoded1);
	BigPoly encoded2 = encoder.encode(3);
	BigPoly encrypted2 = encryptor.encrypt(encoded2);

	Evaluator evaluator(parms, *evaluation_keys);

	BigPoly decrypted1 = decryptor.decrypt(encrypted1);
	cout << encoder.decode_int32(decrypted1);*/

	/*ofstream par_file("HE_Context/parms.out", ios::out | ios::binary);
	parms.save(par_file);
	par_file.flush();
	// cout << parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	ofstream pk_file("HE_Context/pk.out", ios::out | ios::binary);
	public_key->save(pk_file);
	pk_file.flush();
	// cout << public_key.coeff_uint64_count() << endl;

	ofstream sk_file("HE_Context/sk.out", ios::out | ios::binary);
	secret_key->save(sk_file);
	sk_file.flush();

	ofstream ek_file("HE_Context/ek.out", ios::out | ios::binary);
	evaluation_keys->save(ek_file);
	ek_file.flush();*/
	// cout << "eval.count = " << evaluation_keys.count() << endl;

	cout << "Generare de chei incheiata.\n";
}

/*HE_Signal::HE_Signal()
{
!!!!!!!!!! ios::binary FARA SETAREA FLAG-ULUI APARE O EROARE LA INCARCAREA CHEILOR DE EVALLUARE
	ifstream in;
	in.open("par.out");
	parms.load(in);
	in.close();

	cout << parms.coeff_modulus().significant_bit_count() << " bits per coefficient" << endl;

	in.open("pk.out");
	(*public_key).load(in);
	cout << (*public_key).coeff_uint64_count() << endl;
	in.close();

	in.open("sk.out");
	(*secret_key).load(in);
	in.close();

	in.open("ek.out");
	(*evaluation_keys).load(in);
	cout << "eval.count = " << (*evaluation_keys).count() << endl;
	in.close();
}*/

HE_Signal::~HE_Signal()
{
	delete secret_key;
	delete public_key;
	delete evaluation_keys;
}

void HE_Signal::encrypt_signal(vector<int> &plain_samples, vector<BigPoly> &encrypted_samples)const
{
	BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, *public_key);

	encrypted_samples.clear();
	encrypted_samples.reserve(plain_samples.size());
	for (int i = 0; i < plain_samples.size(); i++)
	{
		BigPoly encoded = encoder.encode(plain_samples[i]);
		BigPoly encrypted = encryptor.encrypt(encoded);
		encrypted_samples.push_back(encrypted);
	}
}

void HE_Signal::decrypt_signal(vector<int> &plain_samples, vector<BigPoly> &encrypted_samples)const
{
	BalancedEncoder encoder(parms.plain_modulus());
	Decryptor decryptor(parms, *secret_key);

	plain_samples.clear();
	plain_samples.reserve(encrypted_samples.size());
	for (int i = 0; i < encrypted_samples.size(); i++)
	{
		BigPoly decrypted = decryptor.decrypt(encrypted_samples[i]);
		int decoded = encoder.decode_int32(decrypted);
		plain_samples.push_back(decoded);
	}
}

void HE_Signal::decrypt_no_relin(vector<int > &plain_samples, vector<BigPoly> &encrypted_samples)const
{
	BalancedEncoder encoder(parms.plain_modulus());
	Decryptor decryptor(parms, *secret_key, 2);

	plain_samples.clear();
	plain_samples.reserve(encrypted_samples.size());
	for (int i = 0; i < encrypted_samples.size(); i++)
	{
		BigPoly decrypted = decryptor.decrypt(encrypted_samples[i]);
		int decoded = encoder.decode_int32(decrypted);
		plain_samples.push_back(decoded);
	}
}

void HE_Signal::mult_enc_signals(vector<BigPoly> &enc_s1,
	vector<BigPoly> &enc_s2, vector<BigPoly> &mult)const
{
	// !!! brute force multiplication between polynomials
	int length = enc_s1.size() + enc_s2.size() - 1;
	mult.reserve(length);

	/*BalancedEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, *public_key);
	for (int i = 0; i < length; i++)
	{
		BigPoly encoded = encoder.encode(0);
		mult.push_back(encryptor.encrypt(encoded));
	}*/

	Evaluator evaluator(parms, *evaluation_keys);
	BigPoly encryptedproduct;

	vector<vector<BigPoly> > vertical_vectors(length);
	// vertical_0 = a_0 * b_0
	// vertical_1 = a_0*b_1 + a_1*b_0 s.a.m.d.

	for (int i = 0; i < enc_s1.size(); i++)
	{
		for (int j = 0; j < enc_s2.size(); j++)
		{
			// mult[i + j] = enc_s1[i] * enc_s2[j];
			// BigPoly encryptedproduct = evaluator.multiply(enc_s1[i], enc_s2[j]);
			// mult[i+j] = evaluator.add(mult[i+j], encryptedproduct);
			BigPoly a_i_mult_b_j = evaluator.multiply_norelin(enc_s1[i], enc_s2[j]);
			vertical_vectors[i + j].push_back(a_i_mult_b_j);
		}
	}

	for (int i = 0; i < length; i++)
	{
		BigPoly result = evaluator.add_many(vertical_vectors[i]);
		mult.push_back(result);
	}

	// BigPoly decrypted = decryptor.decrypt(mult[0]);
	// int decoded = encoder.decode_int32(decrypted);
}

void HE_Signal::conv_window_method(vector<BigPoly> &filter, vector<BigPoly> &signal, vector<BigPoly> &result)const
{

}

void mult_plain_signals(vector<int> &s1, vector<int> &s2, vector<int> &s_mult)
{
	int length = s1.size() + s2.size() - 1;
	vector<int> mult(length);
	for (int i = 0; i < length; i++)
	{
		mult[i] = 0;
	}

	for (int i = 0; i < s1.size(); i++)
	{
		for (int j = 0; j < s2.size(); j++)
		{
			mult[i + j] += s1[i] * s2[j];
		}
	}

	s_mult = mult;
}

void read_signal(const char *filename, vector<int> &signal)
{
	ifstream in;
	in.open(filename);
	signal.clear();
	int pondere;
	while (in >> pondere)
	{
		signal.push_back(pondere);
	}
	in.close();
}

void write_signal(const char *filename, vector<int> &signal)
{
	ofstream out;
	out.open(filename);
	for (int i = 0; i < signal.size(); i++)
	{
		out << (int)signal[i] << endl;
	}
	out.close();
}