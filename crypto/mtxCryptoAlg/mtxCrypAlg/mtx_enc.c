#include <string.h>
#include <time.h>

#include "./mtxEcdsa/mtx.h"
#include "./mtxHash/mtxHash.h"

#if defined(POLARSSL_PLATFORM_C)
#include "./polarssl/platform.h"
#else
#include <stdlib.h>
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#include "./polarssl/hmac_drbg.h"


int _mtx_check_version(mtx_version mtxver)
{
	if (!((mtxver== mtx_VER_1) || (mtxver== mtx_VER_2)))
	{
		return 0;
	}

	return 1;
}

int _mtx_check_sig_type(mtx_sig_type mtxsigtype)
{
	if (!((mtxsigtype== mtx_SIG_TYPE_NORM) || (mtxsigtype== mtx_SIG_TYPE_CERT)))
	{
		return 0;
	}

	return 1;
}

int _mtx_encrypt_size(mtx_keypair *eckey, const unsigned int uiPlainLen)
{
	int	iRtn = 0;

	size_t	sizeKeyLen = 0, sizeC1Len = 0, sizeC2Len = 0, sizeC3Len = 0;

	mtx_ASSERT_NEQ_EX(eckey, 0, -1);

	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -2);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -3);

	sizeKeyLen = ((eckey->grp.nbits + 7) / 8);
	sizeC1Len = 2 * sizeKeyLen;
	mtx_ASSERT_NEQ_EX(sizeC1Len, 0, -1);
	sizeC2Len = uiPlainLen;
	sizeC3Len = mtxHash_DIGEST_LENGTH;

	iRtn = (int)(sizeC1Len + sizeC2Len + sizeC3Len);//C1+C2+C3
END:
	return iRtn;
}

int _mtx_decrypt_size(mtx_keypair *eckey, const unsigned int uiCipherLen)
{
	int	iRtn = 0;

	size_t	sizeKeyLen = 0, sizeC1Len = 0, sizeC2Len = 0, sizeC3Len = 0;

	mtx_ASSERT_NEQ_EX(eckey, 0, -1);

	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	sizeKeyLen = ((eckey->grp.nbits + 7) / 8);
	sizeC1Len = 2 * sizeKeyLen;
	mtx_ASSERT_NEQ_EX(sizeC1Len, 0, -1);
	sizeC3Len = mtxHash_DIGEST_LENGTH;
	if (((unsigned int)(sizeC1Len + sizeC3Len)) > uiCipherLen)
	{
		iRtn = -1;
		goto END;
	}
	sizeC2Len = (size_t)(uiCipherLen) - sizeC1Len - sizeC3Len;

	iRtn = (int)(sizeC2Len);//C2, UGLY TRANSFORM
END:
	return iRtn;
}

int mtx_encrypt(const unsigned char *dgst, unsigned int dgstlen, unsigned char *cipher, unsigned int *cipherlen, mtx_keypair *eckey)
{
	return _mtx_encrypt(dgst, dgstlen, cipher, cipherlen, eckey, mtx_VER_2);
}

int mtx_decrypt(const unsigned char *cipher, unsigned int cipherlen, unsigned char *dgst, unsigned int *dgstlen, mtx_keypair *eckey)
{
	return _mtx_decrypt(cipher, cipherlen, dgst, dgstlen, eckey, mtx_VER_2);
}

int _mtx_encrypt(const unsigned char *pbPlain, unsigned int uiPlainLen,
	unsigned char *pbCipher, unsigned int *puiCipherLen, mtx_keypair *eckey, mtx_version mtxver)
{
	int iRtn = 0;

	unsigned char	*pbT = NULL, *pbKP = NULL, *pbC1 = NULL, *pbC2 = NULL, pbC3[mtxHash_DIGEST_LENGTH] = {0}, *pbXMY = NULL;
	unsigned int	uiKeyLen = 0, uiC1Len = 0, uiC2Len = 0, uiC3Len = 0;

	mtxHash_CTX	mtxHashctx;

	hmac_drbg_context	*rng_ctx = 0;
	const md_info_t	*md_info = 0;
	unsigned char	rnd[POLARSSL_ECP_MAX_BYTES] = { 0 };

	mpi	*pmpiK = 0, *pmpiH = 0;
	ecp_point *ptC1 = 0, *ptS = 0, *ptKP = 0;

	mtx_ASSERT_NEQ_EX(pbPlain, 0, 0);
	mtx_ASSERT_NEQ_EX(uiPlainLen, 0, 0);
	mtx_ASSERT_NEQ_EX(puiCipherLen, 0, 0);
	mtx_ASSERT_NEQ_EX(eckey, 0, 0);
	mtx_ASSERT_NEQ_EX(_mtx_check_version(mtxver), 0, 0);

	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	//set lens and check if need to return
	uiKeyLen = (unsigned int)((eckey->grp.nbits + 7) / 8);
	uiC1Len = 2 * uiKeyLen;
	mtx_ASSERT_NEQ_EX(uiC1Len, 0, 0);
	uiC2Len = uiPlainLen;
	uiC3Len = mtxHash_DIGEST_LENGTH;
	if (!pbCipher)
	{
		*puiCipherLen = uiC1Len + uiC2Len + uiC3Len;
		iRtn = 1;
		goto END;
	}

	//set random context
	md_info = md_info_from_type(POLARSSL_MD_SHA256);
	mtx_ASSERT_NEQ_EX(md_info, 0, 0);
	rng_ctx = (hmac_drbg_context*)polarssl_malloc(sizeof(hmac_drbg_context));
	mtx_ASSERT_NEQ_EX(rng_ctx, 0, 0);
	iRtn = hmac_drbg_init(rng_ctx, md_info, mtx_rand, 0, 0, 0);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//calc random k = random[1,bnN)
	pmpiK = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiK, 0, 0);
	mpi_init(pmpiK);
	do
	{
		iRtn = hmac_drbg_random(rng_ctx, rnd, uiKeyLen);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		iRtn = mpi_read_binary(pmpiK, rnd, uiKeyLen);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		iRtn = mpi_shift_r(pmpiK, 8 * uiKeyLen - eckey->grp.nbits);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	} while (mpi_cmp_int(pmpiK, 1) < 0 || mpi_cmp_mpi(pmpiK, &eckey->grp.N) >= 0);

	//calc point ptC1 and convert it to bit stream pbC1
	ptC1 = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptC1, 0, 0);
	ecp_point_init(ptC1);
	iRtn = ecp_mul(&eckey->grp, ptC1, pmpiK, &eckey->grp.G, hmac_drbg_random, rng_ctx);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	//convert ptC1 to pbC1
	pbC1 = (unsigned char*)polarssl_malloc(2 * uiKeyLen);
	mtx_ASSERT_NEQ_EX(pbC1, 0, 0);
	iRtn = mpi_write_binary(&ptC1->X, pbC1, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_write_binary(&ptC1->Y, pbC1 + uiKeyLen, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//calc ptS=[bnH]ptPubKey and check ptS
	pmpiH = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiH, 0, 0);
	mpi_init(pmpiH);
// 	iRtn = mpi_read_binary(pmpiH, (unsigned char *)(&eckey->grp.h), sizeof(eckey->grp.h));
// 	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_set_bit(pmpiH, 0, 1);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	ptS = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptS, 0, 0);
	ecp_point_init(ptS);
	iRtn = ecp_mul(&eckey->grp, ptS, pmpiH, &eckey->Q, hmac_drbg_random, rng_ctx);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_cmp_int(&ptS->Z, 0);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);

	//calc ptKP=[k]ptPubKey and convert it to pbKP
	ptKP = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptKP, 0, 0);
	ecp_point_init(ptKP);
	iRtn = ecp_mul(&eckey->grp, ptKP, pmpiK, &eckey->Q, hmac_drbg_random, rng_ctx);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	pbKP = (unsigned char*)polarssl_malloc(2 * uiKeyLen);
	mtx_ASSERT_NEQ_EX(pbKP, 0, 0);
	iRtn = mpi_write_binary(&ptKP->X, pbKP, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_write_binary(&ptKP->Y, pbKP + uiKeyLen, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//calc pbT = KDF(pbKP,uiPlainLen)
	pbT = (unsigned char *)polarssl_malloc(uiPlainLen);
	mtx_ASSERT_NEQ_EX(pbT, 0, 0);
	iRtn = mtx_KDF(pbKP, 2 * uiKeyLen, pbT, uiPlainLen, 1);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);
	if (pbKP)
	{
		polarssl_free(pbKP);
		pbKP = NULL;
	}

	//calc pbC2
	pbC2 = (unsigned char *)polarssl_malloc(uiC2Len);
	mtx_ASSERT_NEQ_EX(pbC2, 0, 0);
	xorData(pbC2, pbT, pbPlain, uiC2Len);
	if (pbT)
	{
		polarssl_free(pbT);
		pbT = NULL;
	}

	//calc pbC3 = Hash(X || M || Y)
	pbXMY = (unsigned char *)polarssl_malloc(uiPlainLen + 2 * uiKeyLen);
	mtx_ASSERT_NEQ_EX(pbXMY, 0, 0);
	iRtn = mpi_write_binary(&ptKP->X, pbXMY, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	memcpy(pbXMY + uiKeyLen, pbPlain, uiPlainLen);
	iRtn = mpi_write_binary(&ptKP->Y, pbXMY + uiKeyLen + uiPlainLen, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	mtxHash_INIT(&mtxHashctx);
	mtxHash_UPDATE(&mtxHashctx, pbXMY, uiPlainLen + 2 * uiKeyLen);
	mtxHash_FINAL(pbC3, &mtxHashctx);
	if (pbXMY)
	{
		polarssl_free(pbXMY);
		pbXMY = NULL;
	}

	//calc pbCipher, which length is PointLen(c1) + PlainLen(c2) + mtxHash_DIGEST_LEN(c3)
	if (mtxver == mtx_VER_1)
	{
		memcpy(pbCipher, pbC1, uiC1Len);
		memcpy(pbCipher + uiC1Len, pbC2, uiC2Len);
		memcpy(pbCipher + uiC1Len + uiC2Len, pbC3, uiC3Len);
	}
	else if (mtxver == mtx_VER_2)
	{
		memcpy(pbCipher, pbC1, uiC1Len);
		memcpy(pbCipher + uiC1Len, pbC3, uiC3Len);
		memcpy(pbCipher + uiC1Len + uiC3Len, pbC2, uiC2Len);
	}
	*puiCipherLen = uiC1Len + uiC2Len + uiC3Len;

	iRtn = 1;
END:
	if (rng_ctx)
	{
		hmac_drbg_free(rng_ctx);
		polarssl_free(rng_ctx);
		rng_ctx = 0;
	}
	if (pmpiK)
	{
		mpi_free(pmpiK);
		polarssl_free(pmpiK);
		pmpiK = 0;
	}
	if (ptC1)
	{
		ecp_point_free(ptC1);
		polarssl_free(ptC1);
		ptC1 = 0;
	}
	if (pbC1)
	{
		polarssl_free(pbC1);
		pbC1 = 0;
	}
	if (pmpiH)
	{
		mpi_free(pmpiH);
		polarssl_free(pmpiH);
		pmpiH = 0;
	}
	if (ptS)
	{
		ecp_point_free(ptS);
		polarssl_free(ptS);
		ptS = 0;
	}
	if (ptKP)
	{
		ecp_point_free(ptKP);
		polarssl_free(ptKP);
		ptKP = 0;
	}
	if (pbKP)
	{
		polarssl_free(pbKP);
		pbKP = 0;
	}
	if (pbT)
	{
		polarssl_free(pbT);
		pbT = 0;
	}
	if (pbC2)
	{
		polarssl_free(pbC2);
		pbC2 = 0;
	}
	if (pbXMY)
	{
		polarssl_free(pbXMY);
		pbXMY = 0;
	}

	return iRtn;
}


int _mtx_decrypt(const unsigned char *pbCipher, unsigned int uiCipherLen,
			   unsigned char *pbPlain, unsigned int *puiPlainLen, mtx_keypair *eckey, mtx_version mtxver)
{
	int iRtn = 0;

	unsigned char	*pbC1 = NULL, *pbC2 = NULL, pbC3[mtxHash_DIGEST_LENGTH] = {0}, pbC3X[mtxHash_DIGEST_LENGTH] = {0}, *pbX2Y2 = NULL, *pbT = NULL, *pbXMY = NULL;
	unsigned int	uiC1Len = 0, uiC2Len = 0, uiC3Len = 0, uiKeyLen = 0, i = 0;

	mtxHash_CTX mtxHashctx;
	
	ecp_point	*ptC1 = NULL;
	ecp_point	*ptS = NULL;
	ecp_point	*ptDC1 = NULL;

	hmac_drbg_context	*rng_ctx = 0;
	const md_info_t	*md_info = 0;

	mpi	*pmpiH = 0;

	mtx_ASSERT_NEQ_EX(pbCipher, 0, 0);
	mtx_ASSERT_NEQ_EX(uiCipherLen, 0, 0);
	mtx_ASSERT_NEQ_EX(puiPlainLen, 0, 0);
	mtx_ASSERT_NEQ_EX(eckey, 0, 0);
	mtx_ASSERT_NEQ_EX(_mtx_check_version(mtxver), 0, 0);

	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	//set lens and check if need to return
	uiKeyLen = (unsigned int)((eckey->grp.nbits + 7) / 8);
	uiC1Len = 2 * uiKeyLen;
	mtx_ASSERT_NEQ_EX(uiC1Len, 0, 0);
	uiC3Len = mtxHash_DIGEST_LENGTH;
	uiC2Len = uiCipherLen - uiC1Len - uiC3Len;
	if (!pbPlain)
	{
		*puiPlainLen = uiC2Len;
		iRtn = 1;
		goto END;
	}

	//get pbC1, calc ptC1 and check ptC1
	pbC1 = (unsigned char*)polarssl_malloc(uiC1Len);
	mtx_ASSERT_NEQ_EX(pbC1, 0, 0);
	memcpy(pbC1, pbCipher, uiC1Len);//get C1
	ptC1 = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptC1, 0, 0);
	ecp_point_init(ptC1);
	iRtn = mpi_read_binary(&ptC1->X, pbC1, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_read_binary(&ptC1->Y, pbC1 + uiKeyLen, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	if (pbC1)
	{
		polarssl_free(pbC1);
		pbC1 = NULL;
	}
	iRtn = mpi_set_bit(&ptC1->Z, 0, 1);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = ecp_check_pubkey(&eckey->grp, ptC1);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	//set random context
	md_info = md_info_from_type(POLARSSL_MD_SHA256);
	mtx_ASSERT_NEQ_EX(md_info, 0, 0);
	rng_ctx = (hmac_drbg_context*)polarssl_malloc(sizeof(hmac_drbg_context));
	mtx_ASSERT_NEQ_EX(rng_ctx, 0, 0);
	iRtn = hmac_drbg_init(rng_ctx, md_info, mtx_rand, 0, 0, 0);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//set get bnH, calc ptS, check if ptS is infinit
	pmpiH = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiH, 0, 0);
	mpi_init(pmpiH);
	iRtn = mpi_read_binary(pmpiH, (unsigned char *)(&eckey->grp.h), sizeof(eckey->grp.h));
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	ptS = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptS, 0, 0);
	ecp_point_init(ptS);
	iRtn = ecp_mul(&eckey->grp, ptS, pmpiH, &eckey->Q, hmac_drbg_random, rng_ctx);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_cmp_int(&ptS->Z, 0);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);

	//calc ptDC1=[privKey]*ptC1, and get pbX2Y2, pbX2, pbY2
	ptDC1 = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptDC1, 0, 0);
	ecp_point_init(ptDC1);
	iRtn = ecp_mul(&eckey->grp, ptDC1, &eckey->d, ptC1, hmac_drbg_random, rng_ctx);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	pbX2Y2 = (unsigned char *)polarssl_malloc(uiKeyLen * 2);
	mtx_ASSERT_NEQ_EX(pbX2Y2, 0, 0);
	iRtn = mpi_write_binary(&ptDC1->X, pbX2Y2, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_write_binary(&ptDC1->Y, pbX2Y2 + uiKeyLen, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//calc pbT = KDF(pbX2Y2, uiC2Len), check if pbT is zeros, calc pbPlain=pbT^pbC2
	pbT = (unsigned char *)polarssl_malloc(uiC2Len);
	mtx_ASSERT_NEQ_EX(pbT, 0, 0);
	iRtn = mtx_KDF(pbX2Y2, uiKeyLen * 2, pbT, uiC2Len, 1);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);
	for (i=0; i<uiC2Len; i++)
	{
		if (pbT[i] != 0)
		{
			break;
		}
	}
	mtx_ASSERT_NEQ_EX(i, uiC2Len, 0);
	pbC2 = (unsigned char *)polarssl_malloc(uiC2Len);
	mtx_ASSERT_NEQ_EX(pbC2, 0, 0);
	if (mtxver == mtx_VER_1)
	{
		memcpy(pbC2, pbCipher+uiC1Len, uiC2Len);//get C2
	}
	else if (mtxver == mtx_VER_2)
	{
		memcpy(pbC2, pbCipher+uiC1Len+uiC3Len, uiC2Len);//get C2
	}
	xorData(pbPlain, pbT, pbC2, uiC2Len);
	if (pbX2Y2)
	{
		polarssl_free(pbX2Y2);
		pbX2Y2 = NULL;
	}
	if (pbT)
	{
		polarssl_free(pbT);
		pbT = NULL;
	}
	if (pbC2)
	{
		polarssl_free(pbC2);
		pbC2 = NULL;
	}

	//calc pbC3' and check pbC3'==pbC3
	pbXMY = (unsigned char *)polarssl_malloc(uiC2Len + 2 * uiKeyLen);
	mtx_ASSERT_NEQ_EX(pbXMY, 0, 0);
	iRtn = mpi_write_binary(&ptDC1->X, pbXMY, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	memcpy(pbXMY + uiKeyLen, pbPlain, uiC2Len);
	iRtn = mpi_write_binary(&ptDC1->Y, pbXMY + uiKeyLen + uiC2Len, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	if (mtxver == mtx_VER_1)
	{
		memcpy(pbC3, pbCipher + uiC1Len + uiC2Len, uiC3Len);//get C3
	}
	else if (mtxver == mtx_VER_2)
	{
		memcpy(pbC3, pbCipher + uiC1Len, uiC3Len);//get C3
	}
	mtxHash_INIT(&mtxHashctx);
	mtxHash_UPDATE(&mtxHashctx, pbXMY, uiC2Len + 2 * uiKeyLen);
	mtxHash_FINAL(pbC3X, &mtxHashctx);
	iRtn = memcmp(pbC3, pbC3X, uiC3Len);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	if (pbXMY)
	{
		polarssl_free(pbXMY);
		pbXMY = NULL;
	}

	*puiPlainLen = uiC2Len;
	iRtn = 1;
END:
	if (pbC1)
	{
		polarssl_free(pbC1);
		pbC1 = NULL;
	}

	if (pbC2)
	{
		polarssl_free(pbC2);
		pbC2 = NULL;
	}

	if (pbX2Y2)
	{
		polarssl_free(pbX2Y2);
		pbX2Y2 = NULL;
	}

	if (pbT)
	{
		polarssl_free(pbT);
		pbT = NULL;
	}

	if (pbXMY)
	{
		polarssl_free(pbXMY);
		pbXMY = NULL;
	}
	if (ptC1)
	{
		ecp_point_free(ptC1);
		polarssl_free(ptC1);
		ptC1 = NULL;
	}

	if (ptS)
	{
		ecp_point_free(ptS);
		polarssl_free(ptS);
		ptS = NULL;
	}

	if (ptDC1)
	{
		ecp_point_free(ptDC1);
		polarssl_free(ptDC1);
		ptDC1 = NULL;
	}

	if (pmpiH)
	{
		mpi_free(pmpiH);
		polarssl_free(pmpiH);
		pmpiH = NULL;
	}

	if (rng_ctx)
	{
		hmac_drbg_free(rng_ctx);
		polarssl_free(rng_ctx);
		rng_ctx = 0;
	}

	return iRtn;
}