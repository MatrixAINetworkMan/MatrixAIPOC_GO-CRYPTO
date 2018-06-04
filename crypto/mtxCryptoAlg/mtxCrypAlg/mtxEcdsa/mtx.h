#ifndef HEADER_mtx_H
#define HEADER_mtx_H

#include "mtx_util.h"
#include <time.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define mtx_BITS_LEN	256
#define mtx_BYTES_LEN	(mtx_BITS_LEN / 8)

typedef enum
{
	mtx_VER_1,
	mtx_VER_2
} mtx_version;

typedef enum
{
	mtx_SIG_TYPE_NORM,
	mtx_SIG_TYPE_CERT
} mtx_sig_type;

int _mtx_check_version(mtx_version mtxver);

int _mtx_check_sig_type(mtx_sig_type mtxsigtype);

int _mtx_sign_size(mtx_keypair *eckey);

int _mtx_encrypt_size(mtx_keypair *eckey, const unsigned int uiPlainLen);

int _mtx_decrypt_size(mtx_keypair *eckey, const unsigned int uiCipherLen);

/*
* computes encrypt
* \param dgst: to be encrypted messages
* \param dgstlen: message length to be encrypted
* \param cipher: buffer to hold the Encrypted ciphertext
* \param ciperlen: the length of the Encrypted ciphertext
* \param eckey: pointer to the mtx_keypair object containing a public EC key
* \return 1 on success and 0 otherwise
*/
int mtx_encrypt(const unsigned char *dgst, unsigned int dgstlen, unsigned char *cipher, unsigned int *cipherlen, mtx_keypair *eckey);

/*
* computes Decrypt
* \param cipher: to be Decrypted messages
* \param cipherlen: message length to be Decrypted
* \param dgst: buffer to hold the Decrypted ciphertext
* \param dgstlen: the length of the Decrypted ciphertext
* \param eckey: pointer to the mtx_keypair object containing a private EC key
* \return 1 on success and 0 otherwise
*/
int mtx_decrypt(const unsigned char *cipher, unsigned int cipherlen, unsigned char *dgst, unsigned int *dgstlen, mtx_keypair *eckey);

/*
* computes ECDSA signature of a given hash value using the supplied
* private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
* \param dgst: pointer to the hash value to sign
* \param dgstlen: length of the hash value
* \param sig: buffer to hold the DER encoded signature
* \param siglen: pointer to the length of the returned signature
* \param eckey: pointer to the mtx_keypair object containing a private EC key
* \return 1 on success and 0 otherwise
*/
int	mtx_sign(const unsigned char *dgst, unsigned int dlen, unsigned char *sig, unsigned int *siglen, mtx_keypair *eckey);

/*
* verifies that the given signature is valid ECDSA signature
* of the supplied hash value using the specified public key
* \param dgst: pointer to the hash value
* \param dgstlen: length of the hash value
* \param sig:  pointer to the DER encoded signature
* \param siglen: length of the DER encoded signature
* \param eckey: pointer to the mtx_keypair object containing a public EC key
* \return 1 if the signature is valid, 0 if the signature is invalid and -1 on error
*/
int mtx_verify(const unsigned char *dgst, unsigned int dlen, const unsigned char *sigbuf, unsigned int siglen, mtx_keypair *eckey);


int _mtx_sign_ex(const unsigned char *pbIDValue, unsigned int IDLen,
				const unsigned char *m, unsigned int m_length,
				unsigned char *sigret, unsigned int *siglen, mtx_keypair *eckey);

int _mtx_verify_ex(const unsigned char *pbIDValue, unsigned int IDLen,
				  const unsigned char *m, unsigned int m_length,
				  const unsigned char *sigbuf, unsigned int siglen, mtx_keypair *eckey);


int mtx_genAgreementData(const unsigned char *pbSponsorID, const unsigned int uiSponsorIDLen, \
						 const mtx_keypair *eckey_sponsor, const unsigned int uiSessKeyLen, \
						 ecp_point **pubkey_sponsor_tmp, mtx_keypair **eckey_sponsor_tmp);

int mtx_genAgreementDataAndKey(const unsigned char *pbSponsorID, const unsigned int uiSponsorIDLen, \
							   const unsigned char *pbReceiverID, const unsigned int uiReceiverIDLen, \
							   const ecp_point *pubkey_sponsor, const ecp_point *pubkey_sponsor_tmp, \
							   const mtx_keypair *eckey_receiver, const unsigned int uiSessKeyLen, \
							   ecp_point **pubkey_receiver_tmp, mtx_keypair **eckey_receiver_tmp, \
							   unsigned char *pbSessKey, unsigned char *pbSB, unsigned char *pbS2);

int mtx_genKey(const unsigned char *pbSponsorID, const unsigned int uiSponsorIDLen, \
			   const unsigned char *pbReceiverID, const unsigned int uiReceiverIDLen, \
			   const ecp_point *pubkey_receiver, const ecp_point *pubkey_receiver_tmp, \
			   const mtx_keypair *eckey_sponsor, const mtx_keypair *eckey_tmp_sponsor, \
			   const unsigned int uiSessKeyLen, unsigned char *pbSessKey, \
			   const unsigned char *pbSB, unsigned char *pbSA);


static int mtx_rand(void *rng_state, unsigned char *output, size_t len)
{
	size_t use_len;
	int rnd;

	if (rng_state != NULL)
	{
		rng_state = NULL;
	}

	srand((int)time(0));

	while (len > 0)
	{
		use_len = len;
		if (use_len > sizeof(int))
		{
			use_len = sizeof(int);
		}

		rnd = rand();
		memcpy(output, &rnd, use_len);
		output += use_len;
		len -= use_len;
	}

	return 0;
}

			   
#ifdef  __cplusplus
}
#endif
#endif