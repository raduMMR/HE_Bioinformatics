#include "HE_Batch_Signal.h"
#include <assert.h>

#define _TEST_HE_CONV_ 

HE_Batch_Signal::HE_Batch_Signal(const char* poly_modulus, int plain_modulus,
	int decomposition_bit_count, const char *coeff_modulus):
	 HE_Signal(poly_modulus, plain_modulus, decomposition_bit_count, coeff_modulus)

{
	Encryptor encryptor(parms, *public_key);

	crtbuilder = new PolyCRTBuilder(parms.plain_modulus(), parms.poly_modulus());
	slot_count = crtbuilder->get_slot_count();

	vector<BigUInt> masca(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(1)));
	masca[0] = 0;

	encrypted_masks = vector<BigPoly>(slot_count);

#ifdef _TEST_HE_CONV_
	for (int i = 0; i < 4; i++)
	{
		BigPoly masca_i = crtbuilder->compose(masca);
		encrypted_masks[i] = encryptor.encrypt(masca_i);

		masca[i] = 1;
		if (i + 1 < slot_count)
			masca[i + 1] = 0;
	}
#else
	for (int i = 0; i < slot_count; i++)
	{
		BigPoly masca_i = crtbuilder->compose(masca);
		encrypted_masks[i] = encryptor.encrypt(masca_i);

		masca[i] = 1;
		if (i + 1 < slot_count)
			masca[i + 1] = 0;
	}
#endif

}

HE_Batch_Signal::~HE_Batch_Signal()
{
	delete crtbuilder;
}

void HE_Batch_Signal::set_filter(vector<int> filter_coeffs)
{
	int nr_coeffs = filter_coeffs.size();
	filter_enc_coeffs = vector<BigPoly>(nr_coeffs);

	Encryptor encryptor(parms, *public_key);

	for (int i = 0; i < nr_coeffs; i++)
	{
		// initializeaza values cu acelasi coeficient in toate slot-urile
		vector<BigUInt> values(slot_count,
			BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(filter_coeffs[i])));
		BigPoly crt_coeff = crtbuilder->compose(values);
		filter_enc_coeffs[i] = encryptor.encrypt(crt_coeff);
	}

	/*vector<BigUInt> values(slot_count,
		BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	BigPoly crt_coeff = crtbuilder->compose(values);
	BigPoly zero_coeff = encryptor.encrypt(crt_coeff);
	for (int i = nr_coeffs; i < slot_count; i++)
	{
		filter_enc_coeffs[i] = zero_coeff;
	}*/

}

void HE_Batch_Signal::encrypt_signal(vector<int> &signal_coeffs, vector<vector<BigPoly> > &encrypted_windows)const
{
	cout << endl << "Se cripteaza semnalul ..." << endl;

	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	Encryptor encryptor(parms, *public_key);

	// fiecare slot_count coeficienti vor fi criptati intr-un singur ctxt
	// de slot_count ori pentru fiecare permutare a sloturilor'
	int nr_ferestre = signal_coeffs.size() / slot_count;
	int coeff_ultima_fereastra = signal_coeffs.size() % slot_count;

	if (coeff_ultima_fereastra == 0)
	{
		encrypted_windows = vector <vector<BigPoly> >(nr_ferestre);
	}
	else
	{
		encrypted_windows = vector <vector<BigPoly> >(nr_ferestre+1);
	}

	for (int i = 0; i< nr_ferestre; i++)
	{
		for (int j = 0; j < slot_count; j++)
		{
			values[j] = signal_coeffs[i*slot_count + j];
		}
		encrypted_windows[i] = vector<BigPoly>(slot_count);

		// criptarea permutarilor coeficientilor ferestrei
		for (int j = 0; j < slot_count; j++)
		{
			BigPoly permutare_fereastra = crtbuilder->compose(values);
			encrypted_windows[i][j] = encryptor.encrypt(permutare_fereastra);

			// permutarea coeficientilor ferestrei
			BigUInt first_val = values[0];
			for (int i = 0; i < slot_count-1; i++)
			{
				values[i] = values[i + 1];
			}
			values[slot_count - 1] = first_val;
		}
	}

	if (coeff_ultima_fereastra != 0)
	{
		values = vector<BigUInt>(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

		for (int i = 0; i < coeff_ultima_fereastra; i++)
		{
			values[i] = signal_coeffs[nr_ferestre*slot_count + i];
		}

		// ultima fereastra o completam cu zerouri
		vector<BigUInt> zeroes(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
		BigPoly enc_zero = crtbuilder->compose(zeroes);
		encrypted_windows[nr_ferestre] = vector<BigPoly>(slot_count, enc_zero);

		// criptarea permutarilor coeficientilor ferestrei
		for (int i = 0; i < coeff_ultima_fereastra; i++)
		{
			BigPoly permutare_fereastra = crtbuilder->compose(values);
			encrypted_windows[nr_ferestre][i] = encryptor.encrypt(permutare_fereastra);

			// permutarea coeficientilor ferestrei
			BigUInt first_val = values[0];
			for (int i = 0; i < coeff_ultima_fereastra - 1; i++)
			{
				values[i] = values[i + 1];
			}
			values[coeff_ultima_fereastra - 1] = first_val;
		}

		// ramane cu padding cu zero
		/*vector<BigPoly> last_window(coeff_ultima_fereastra);
		for (int i = 0; i < coeff_ultima_fereastra; i++)
		{
			last_window[i] = encrypted_windows[nr_ferestre][i];
		}
		encrypted_windows[nr_ferestre] = last_window;*/

		window_size = coeff_ultima_fereastra;

		cout << "Window_Size = " << window_size << endl;

	}

	cout << "S-a terminat de criptat semnalul." << endl;
	
}

void HE_Batch_Signal::decrypt_signal(vector<int> &signal_coeffs, vector<BigPoly> &encrypted_signal)const
{
	cout << "Se decripteaza semnalul ..." << endl;

	Decryptor decryptor_no_relin(parms, *secret_key);

	signal_coeffs = vector<int>(encrypted_signal.size()-1+slot_count);
	int i = 0;
	for (i = 0; i < encrypted_signal.size()-1; i++)
	{
		BigPoly pt = decryptor_no_relin.decrypt(encrypted_signal[i]);
		// doar coeficientul din slot-ul i ne intereseaza
		signal_coeffs[i] = crtbuilder->get_slot(pt, i).to_double();
	}

	// din ultimul ctxt extragem mesajele corespunzatoare tuturor slot-urilor
	// intrucat acestea reprezinta coeficienti valizi 
	// ultimii slot_count coeficienti ai polinomului rezultat in urma convolutiei
	// la ultimul ctxt extragerea are o forma deosebita : 
	// extragerea se continua incepand cu slot-ul (i+1) pana se ajunge la i din nou
	BigPoly last_ctxt = decryptor_no_relin.decrypt(encrypted_signal[encrypted_signal.size()-1]);
	for (int j=0; j < slot_count; j++)
	{
		signal_coeffs[encrypted_signal.size() - 1 + i] = crtbuilder->get_slot(last_ctxt, i).to_double();
		i = (i + 1) % window_size;		// window_size = 4 pt. exemplul
	}

	cout << "S-a terminat de decriptat semnalul." << endl;
}

void HE_Batch_Signal::filter_signal(vector<vector<BigPoly> > &encrypted_windows, vector<BigPoly> &encrypted_signal)const
{
	assert(filter_enc_coeffs.size() != 0);

	cout << "Se filtreaza semnalul ..." << endl;

	vector<BigUInt> zerouri(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
	Encryptor encryptor(parms, *public_key);
	BigPoly crt_zero = crtbuilder->compose(zerouri);
	BigPoly reziduu = encryptor.encrypt(crt_zero);

	Evaluator evaluator(parms, *evaluation_keys);
	
	encrypted_signal = vector<BigPoly>(encrypted_windows.size() + filter_enc_coeffs.size() - 1);
	int k = 0;

	for (int i = 0; i < encrypted_windows.size(); i++)
	{
		for (int j = 0; j < filter_enc_coeffs.size(); j++)
		{
			// inmulteste coeficientul a_j impachetat in fiecare din cele slot_count sloturi
			// cu permutarea j a ferestrei i
			BigPoly coeff = evaluator.multiply(filter_enc_coeffs[j], encrypted_windows[i][j]);

			// add_many in loc de adunare dupa fiecare pas si apoi exragerea coeficientilor
			coeff = evaluator.add(coeff, reziduu);

			encrypted_signal[k++] = coeff; // slotul j are un coefficient valid, il copiem

			// pregatim reziduul pt. pasul urmator
			reziduu = coeff;
			reziduu = evaluator.multiply(reziduu, encrypted_masks[j]);
			
			// evaluator.relinearize(coeff);
		}
	}

	cout << "S-a terminat de filtrat semnalul." << endl;
}
