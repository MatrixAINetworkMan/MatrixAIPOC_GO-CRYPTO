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



int _mtx_sign_size(mtx_keypair *eckey)
{
	int	iRtn = 0;

	unsigned int	uiKeyLen = 0;

	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -2);

	uiKeyLen = (unsigned int)((eckey->grp.nbits + 7) / 8);

	iRtn = (int)(uiKeyLen * 2);//r+s, UGLY TRANSFORM
END:

	return iRtn;
}

int	mtx_sign(const unsigned char *dgst, unsigned int dlen, unsigned char *sig, unsigned int *siglen, mtx_keypair *eckey)
{
	//ID
	unsigned char pbID[16] = { 0x37, 0x38, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 };

	return _mtx_sign_ex(pbID, sizeof(pbID), dgst, dlen, sig, siglen, eckey);
}

int mtx_verify(const unsigned char *dgst, unsigned int dlen, const unsigned char *sigbuf, unsigned int siglen, mtx_keypair *eckey)
{
	//ID
	unsigned char pbID[16] = { 0x37, 0x38, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 };

	return _mtx_verify_ex(pbID, sizeof(pbID), dgst, dlen, sigbuf, siglen, eckey);
}

int _mtx_sign_ex(const unsigned char *pbIDValue, unsigned int IDLen, const unsigned char *m, unsigned int m_length,
	unsigned char *sigret, unsigned int *siglen, mtx_keypair *eckey)
{
	int iRtn = 0;

	unsigned int	uiZLen = 0;

	unsigned char	*pbMsg = NULL;
	unsigned int	uiMsgLen = 0;

	uiMsgLen = mtxHash_DIGEST_LENGTH/*ZLen*/ + m_length;
	pbMsg = (unsigned char *)polarssl_malloc(uiMsgLen);
	mtx_ASSERT_NEQ_EX(pbMsg, 0, 0);

	//calc Z
	iRtn = mtx_getZ(pbIDValue, IDLen, pbMsg, &uiZLen, eckey);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);
	mtx_ASSERT_EQ_EX(uiZLen, mtxHash_DIGEST_LENGTH, 0);

	//cat the Z||m as the final message
	memcpy(pbMsg+uiZLen, m, m_length);

	iRtn = ecd_sign(pbMsg, uiMsgLen, sigret, siglen, eckey);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);

	iRtn = 1;
END:
	if (pbMsg)
	{
		polarssl_free(pbMsg);
		pbMsg = NULL;
	}

	return iRtn;
}

int _mtx_verify_ex(const unsigned char *pbIDValue, unsigned int IDLen, const unsigned char *m, unsigned int m_length,
	const unsigned char *sigbuf, unsigned int siglen, mtx_keypair *eckey)
{
	int iRtn = 0;

	unsigned int	uiZLen = 0;

	unsigned char	*pbMsg = NULL;
	unsigned int	uiMsgLen = 0;

	uiMsgLen = mtxHash_DIGEST_LENGTH/*ZLen*/ + m_length;
	pbMsg = (unsigned char *)polarssl_malloc(uiMsgLen);
	mtx_ASSERT_NEQ_EX(pbMsg, 0, 0);

	//calc Z
	iRtn = mtx_getZ(pbIDValue, IDLen, pbMsg, &uiZLen, eckey);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);
	mtx_ASSERT_EQ_EX(uiZLen, mtxHash_DIGEST_LENGTH, 0);

	//cat the Z||m as the final message
	memcpy(pbMsg+uiZLen, m, m_length);

	iRtn = ecd_verify(pbMsg, uiMsgLen, sigbuf, siglen, eckey);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);

	iRtn = 1;
END:
	if (pbMsg)
	{
		polarssl_free(pbMsg);
		pbMsg = NULL;
	}

	return iRtn;
}

int mtx_getZ(const unsigned char *pbIDValue, unsigned int IDLen, unsigned char *pbZValue, unsigned int *puiZLen, mtx_keypair *eckey)
{
	int	iRtn = 0;

	mtxHash_CTX	mtxHashctx;
	unsigned int	uiKeyLen = 0; //by byte
	unsigned char	*pbData = NULL, *pbTmpData = NULL;
	unsigned int	uiDataLen = 0;
	unsigned int	uiIDBitLen = 0;

	//input check
	mtx_ASSERT_NEQ_EX(puiZLen, 0, 0);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	if (!pbZValue)
	{
		*puiZLen = mtxHash_DIGEST_LENGTH;
		iRtn = 1;
		goto END;
	}

	uiIDBitLen = (IDLen*8);
	if (uiIDBitLen > 0xffff)
	{
		iRtn = 0;
		goto END;
	}

	if (!pbIDValue)
	{
		IDLen = 0;
	}

	//calc keylen/datalen
	uiKeyLen = (unsigned int)((eckey->grp.nbits + 7) / 8);
	uiDataLen = 2 + IDLen + 6 * uiKeyLen;

	//ENTL(2) + ID(IDLen) + a(uiKeyLen) + b(uiKeyLen) + Gx(uiKeyLen) + Gy(uiKeyLen) + X(uiKeyLen) + Y(uiKeyLen)
	pbData = (unsigned char *)polarssl_malloc(uiDataLen);
	pbTmpData = pbData;

	//ENTL(2)
	if (LittleEndianCheck())
	{
		memcpy(pbTmpData, (unsigned char*)(&uiIDBitLen), 2);
		reverseData(pbTmpData, 2);
	}
	else
	{
		memcpy(pbTmpData, ((unsigned char*)(&uiIDBitLen) + sizeof(uiIDBitLen) - 2), 2);
	}
	pbTmpData += 2;

	//ID(IDLen)
	memcpy(pbTmpData, pbIDValue, IDLen);
	pbTmpData += IDLen;

	//a, b
	iRtn = mpi_write_binary(&eckey->grp.A, pbTmpData, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);
	pbTmpData += uiKeyLen;
	iRtn = mpi_write_binary(&eckey->grp.B, pbTmpData, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);
	pbTmpData += uiKeyLen;

	//Gx, Gy
	iRtn = mpi_write_binary(&eckey->grp.G.X, pbTmpData, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);
	pbTmpData += uiKeyLen;
	iRtn = mpi_write_binary(&eckey->grp.G.Y, pbTmpData, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);
	pbTmpData += uiKeyLen;

	//X, Y
	iRtn = mpi_write_binary(&eckey->Q.X, pbTmpData, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);
	pbTmpData += uiKeyLen;
	iRtn = mpi_write_binary(&eckey->Q.Y, pbTmpData, uiKeyLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);
	pbTmpData += uiKeyLen;

	mtxHash_INIT(&mtxHashctx);
	mtxHash_UPDATE(&mtxHashctx, pbData, uiDataLen);
	mtxHash_FINAL(pbZValue, &mtxHashctx);

	*puiZLen = mtxHash_DIGEST_LENGTH;

	iRtn = 1;
END:
	if (pbData)
	{
		polarssl_free(pbData);
		pbData = NULL;
	}

	return iRtn;
}

int ecd_sign(const unsigned char *m, unsigned int m_length,
	unsigned char *sigret, unsigned int *siglen, mtx_keypair *eckey)
{
	int	iRtn = 0;

	mtxHash_CTX	mtxHashctx;
	unsigned char	pbHashData[mtxHash_DIGEST_LENGTH] = {0};

	mtx_ASSERT_NEQ_EX(m, 0, 0);
	mtx_ASSERT_NEQ_EX(m_length, 0, 0);
	mtx_ASSERT_NEQ_EX(sigret, 0, 0);
	mtx_ASSERT_NEQ_EX(siglen, 0, 0);
	
	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);
	
	//calc e
	mtxHash_INIT(&mtxHashctx);
	mtxHash_UPDATE(&mtxHashctx, (unsigned char*)m, m_length);
	mtxHash_FINAL(pbHashData, &mtxHashctx);

	iRtn = mtx_sign_core(pbHashData, mtxHash_DIGEST_LENGTH, sigret, siglen, eckey);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);

	iRtn = 1;
END:
	return iRtn;
}

int ecd_verify(const unsigned char *m, unsigned int m_length,
	const unsigned char *sigbuf, unsigned int siglen, mtx_keypair *eckey)
{
	int iRtn = 0;

	mtxHash_CTX	mtxHashctx;
	unsigned char	pbHashData[mtxHash_DIGEST_LENGTH] = {0};

	mtx_ASSERT_NEQ_EX(m, 0, 0);
	mtx_ASSERT_NEQ_EX(m_length, 0, 0);
	mtx_ASSERT_NEQ_EX(sigbuf, 0, 0);
	mtx_ASSERT_NEQ_EX(siglen, 0, 0);

	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	//calc e
	mtxHash_INIT(&mtxHashctx);
	mtxHash_UPDATE(&mtxHashctx, (unsigned char*)m, m_length);
	mtxHash_FINAL(pbHashData, &mtxHashctx);

	iRtn = mtx_verify_core(pbHashData, mtxHash_DIGEST_LENGTH, sigbuf, siglen, eckey);
	mtx_ASSERT_NEQ_EX(iRtn, 0, 0);

	iRtn = 1;
END:
	return iRtn;
}

int mtx_sign_core(const unsigned char *m, unsigned int m_length,
			 unsigned char *sigret, unsigned int *siglen, mtx_keypair *eckey)
{
	int	iRtn = 0;

	mpi	*pmpiE = 0, *pmpiK = 0, *pmpiR = 0, *pmpiS = 0, *pmpiTmp = 0, *pmpiTmp2 = 0, *pmpiTmp3 = 0;

	ecp_point	*ptPoint = 0;

	hmac_drbg_context	*rng_ctx = 0;
	const md_info_t	*md_info = 0;
	unsigned char	rnd[POLARSSL_ECP_MAX_BYTES] = { 0 };

	unsigned int	uiRLen = 0;
	unsigned int	uiSLen = 0;
	unsigned int	uiKeyLen = 0;
	

	mtx_ASSERT_NEQ_EX(m, 0, 0);
	mtx_ASSERT_EQ_EX(m_length, mtxHash_DIGEST_LENGTH, 0);
	mtx_ASSERT_NEQ_EX(sigret, 0, 0);
	mtx_ASSERT_NEQ_EX(siglen, 0, 0);

	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	uiKeyLen = (unsigned int)((eckey->grp.nbits + 7) / 8);

	//calc e
	pmpiE = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiE, 0, 0);
	mpi_init(pmpiE);
	iRtn = mpi_read_binary(pmpiE, m, m_length);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//set random context
	md_info = md_info_from_type(POLARSSL_MD_SHA256);
	mtx_ASSERT_NEQ_EX(md_info, 0, 0);
	rng_ctx = (hmac_drbg_context*)polarssl_malloc(sizeof(hmac_drbg_context));
	mtx_ASSERT_NEQ_EX(rng_ctx, 0, 0);
	iRtn = hmac_drbg_init(rng_ctx, md_info, mtx_rand, 0, 0, 0);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	pmpiK = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiK, 0, 0);
	mpi_init(pmpiK);

	pmpiR = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiR, 0, 0);
	mpi_init(pmpiR);

	pmpiS = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiS, 0, 0);
	mpi_init(pmpiS);

	pmpiTmp = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiTmp, 0, 0);
	mpi_init(pmpiTmp);

	pmpiTmp2 = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiTmp2, 0, 0);
	mpi_init(pmpiTmp2);

	pmpiTmp3 = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiTmp3, 0, 0);
	mpi_init(pmpiTmp3);

	ptPoint = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptPoint, 0, 0);
	ecp_point_init(ptPoint);

	do
	{
		//calc random k = random[0,bnN)
		do
		{
			iRtn = hmac_drbg_random(rng_ctx, rnd, uiKeyLen);
			mtx_ASSERT_EQ_EX(iRtn, 0, 0);
			iRtn = mpi_read_binary(pmpiK, rnd, uiKeyLen);
			mtx_ASSERT_EQ_EX(iRtn, 0, 0);
			iRtn = mpi_shift_r(pmpiK, 8 * uiKeyLen - eckey->grp.nbits);
			mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		} while (mpi_cmp_int(pmpiK, 1) < 0 || mpi_cmp_mpi(pmpiK, &eckey->grp.N) >= 0);

		//calc X = [k]*G
		iRtn = ecp_mul(&eckey->grp, ptPoint, pmpiK, &eckey->grp.G, hmac_drbg_random, rng_ctx);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);

		//calc R, bnR=bnE+bnX mod bnN
		iRtn = mpi_add_mpi(pmpiR, pmpiE, &ptPoint->X);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		iRtn = mpi_mod_mpi(pmpiR, pmpiR, &eckey->grp.N);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);

		//bnTmp=bnR+bnK mod bnN, just check
		iRtn = mpi_add_mpi(pmpiTmp, pmpiR, pmpiK);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		iRtn = mpi_mod_mpi(pmpiTmp, pmpiTmp, &eckey->grp.N);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		if ((mpi_cmp_int(pmpiR, 0) == 0) || (mpi_cmp_mpi(pmpiTmp, &eckey->grp.N) == 0))
		{
			continue;
		}

		//calc S
		//bnTmp2=pirv+1
		iRtn = mpi_add_int(pmpiTmp2, &eckey->d, 1);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		iRtn = mpi_mod_mpi(pmpiTmp2, pmpiTmp2, &eckey->grp.N);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		//bnTmp3=(bnTmp2)^(-1) mod bnN
		iRtn = mpi_inv_mod(pmpiTmp3, pmpiTmp2, &eckey->grp.N);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		//bnTmp=bnR*priv mod bnN
		iRtn = mpi_mul_mpi(pmpiTmp, pmpiR, &eckey->d);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		iRtn = mpi_mod_mpi(pmpiTmp, pmpiTmp, &eckey->grp.N);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		//bnTmp2=bnK-bnTmp mod bnN
		iRtn = mpi_sub_mpi(pmpiTmp2, pmpiK, pmpiTmp);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		iRtn = mpi_mod_mpi(pmpiTmp2, pmpiTmp2, &eckey->grp.N);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		//S=bnTmp3 * bnTmp2 mod bnN
		iRtn = mpi_mul_mpi(pmpiS, pmpiTmp3, pmpiTmp2);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);
		iRtn = mpi_mod_mpi(pmpiS, pmpiS, &eckey->grp.N);
		mtx_ASSERT_EQ_EX(iRtn, 0, 0);

		if (mpi_cmp_int(pmpiS, 0) == 0)
		{
			continue;
		}
		else
		{
			break;
		}
	} while (1);

	uiRLen = mpi_size(pmpiR);
	uiSLen = mpi_size(pmpiS);
	uiKeyLen = (unsigned int)((eckey->grp.nbits + 7) / 8);

	iRtn = mpi_write_binary(pmpiR, sigret + uiKeyLen - uiRLen, uiRLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	iRtn = mpi_write_binary(pmpiS, sigret + 2 * uiKeyLen - uiSLen, uiSLen);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	*siglen = 2 * uiKeyLen;

	iRtn = 1;
END:
	if (rng_ctx)
	{
		hmac_drbg_free(rng_ctx);
		polarssl_free(rng_ctx);
		rng_ctx = 0;
	}
	if (pmpiE)
	{
		mpi_free(pmpiE);
		polarssl_free(pmpiE);
		pmpiE = 0;
	}
	if (pmpiK)
	{
		mpi_free(pmpiK);
		polarssl_free(pmpiK);
		pmpiK = 0;
	}
	if (pmpiR)
	{
		mpi_free(pmpiR);
		polarssl_free(pmpiR);
		pmpiR = 0;
	}
	if (pmpiS)
	{
		mpi_free(pmpiS);
		polarssl_free(pmpiS);
		pmpiS = 0;
	}
	if (pmpiTmp)
	{
		mpi_free(pmpiTmp);
		polarssl_free(pmpiTmp);
		pmpiTmp = 0;
	}
	if (pmpiTmp2)
	{
		mpi_free(pmpiTmp2);
		polarssl_free(pmpiTmp2);
		pmpiTmp2 = 0;
	}
	if (pmpiTmp3)
	{
		mpi_free(pmpiTmp3);
		polarssl_free(pmpiTmp3);
		pmpiTmp3 = 0;
	}
	if (ptPoint)
	{
		ecp_point_free(ptPoint);
		polarssl_free(ptPoint);
		ptPoint = 0;
	}

	return iRtn;
}

int mtx_verify_core(const unsigned char *m, unsigned int m_length,
			   const unsigned char *sigbuf, unsigned int siglen, mtx_keypair *eckey)
{
	int iRtn = 0;

	unsigned int	uiKeyLen = 0;
	mpi	*pmpiR = 0, *pmpiS = 0, *pmpiN1 = 0, *pmpiE = 0, *pmpiT = 0, *pmpiRR = 0;

	ecp_point	*ptSG = 0, *ptTP = 0, *ptPoint = 0;

	hmac_drbg_context	*rng_ctx = 0;
	const md_info_t	*md_info = 0;

	mtx_ASSERT_NEQ_EX(m, 0, 0);
	mtx_ASSERT_EQ_EX(m_length, mtxHash_DIGEST_LENGTH, 0);
	mtx_ASSERT_NEQ_EX(sigbuf, 0, 0);
	mtx_ASSERT_NEQ_EX(siglen, 0, 0);

	iRtn = ecp_check_privkey(&eckey->grp, &eckey->d);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	iRtn = ecp_check_pubkey(&eckey->grp, &eckey->Q);
	mtx_ASSERT_EQ_EX(iRtn, 0, -1);

	uiKeyLen = (unsigned int)((eckey->grp.nbits + 7) / 8);
	mtx_ASSERT_EQ_EX(siglen, 2 * uiKeyLen, 0);

	pmpiR = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiR, 0, 0);
	mpi_init(pmpiR);

	pmpiS = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiS, 0, 0);
	mpi_init(pmpiS);

	pmpiN1 = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiN1, 0, 0);
	mpi_init(pmpiN1);

	pmpiE = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiE, 0, 0);
	mpi_init(pmpiE);

	pmpiT = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiT, 0, 0);
	mpi_init(pmpiT);

	pmpiRR = (mpi *)polarssl_malloc(sizeof(mpi));
	mtx_ASSERT_NEQ_EX(pmpiRR, 0, 0);
	mpi_init(pmpiRR);

	ptSG = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptSG, 0, 0);
	ecp_point_init(ptSG);

	ptTP = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptTP, 0, 0);
	ecp_point_init(ptTP);

	ptPoint = (ecp_point *)polarssl_malloc(sizeof(ecp_point));
	mtx_ASSERT_NEQ_EX(ptPoint, 0, 0);
	ecp_point_init(ptPoint);

	//set random context
	md_info = md_info_from_type(POLARSSL_MD_SHA256);
	mtx_ASSERT_NEQ_EX(md_info, 0, 0);
	rng_ctx = (hmac_drbg_context*)polarssl_malloc(sizeof(hmac_drbg_context));
	mtx_ASSERT_NEQ_EX(rng_ctx, 0, 0);
	iRtn = hmac_drbg_init(rng_ctx, md_info, mtx_rand, 0, 0, 0);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//set N-1
	iRtn = mpi_sub_int(pmpiN1, &eckey->grp.N, 1);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//set r and s
	iRtn = mpi_read_binary(pmpiR, sigbuf, siglen / 2);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_read_binary(pmpiS, sigbuf + siglen / 2, siglen / 2);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//check r and s, must 1<= <=N-1
	if ((mpi_cmp_int(pmpiR, 1) < 0) || (mpi_cmp_mpi(pmpiR, pmpiN1) > 0))
	{
		iRtn = 0;
		goto END;
	}
	if ((mpi_cmp_int(pmpiS, 1) < 0) || (mpi_cmp_mpi(pmpiS, pmpiN1) > 0))
	{
		iRtn = 0;
		goto END;
	}

	//calc e
	iRtn = mpi_read_binary(pmpiE, m, m_length);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//calc t = r + s mod n
	iRtn = mpi_add_mpi(pmpiT, pmpiR, pmpiS);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_mod_mpi(pmpiT, pmpiT, &eckey->grp.N);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	//check t
	if (mpi_cmp_int(pmpiT, 0) == 0)
	{
		iRtn = 0;
		goto END;
	}

	//calc [s]G and [t]P, and calc stPoint = SG + TP
	iRtn = ecp_mul(&eckey->grp, ptSG, pmpiS, &eckey->grp.G, hmac_drbg_random, rng_ctx);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = ecp_mul(&eckey->grp, ptTP, pmpiT, &eckey->Q, hmac_drbg_random, rng_ctx);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = ecp_add(&eckey->grp, ptPoint, ptSG, ptTP);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	//calc bnRR=bnE+bnX mod bnN
	iRtn = mpi_add_mpi(pmpiRR, pmpiE, &ptPoint->X);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);
	iRtn = mpi_mod_mpi(pmpiRR, pmpiRR, &eckey->grp.N);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	if (mpi_cmp_mpi(pmpiRR, pmpiR) != 0)
	{
		iRtn = 0;
		goto END;
	}

	iRtn = 1;
END:
	if (rng_ctx)
	{
		hmac_drbg_free(rng_ctx);
		polarssl_free(rng_ctx);
		rng_ctx = 0;
	}
	if (pmpiR)
	{
		mpi_free(pmpiR);
		polarssl_free(pmpiR);
		pmpiR = 0;
	}
	if (pmpiS)
	{
		mpi_free(pmpiS);
		polarssl_free(pmpiS);
		pmpiS = 0;
	}
	if (pmpiN1)
	{
		mpi_free(pmpiN1);
		polarssl_free(pmpiN1);
		pmpiN1 = 0;
	}
	if (pmpiE)
	{
		mpi_free(pmpiE);
		polarssl_free(pmpiE);
		pmpiE = 0;
	}
	if (pmpiT)
	{
		mpi_free(pmpiT);
		polarssl_free(pmpiT);
		pmpiT = 0;
	}
	if (pmpiRR)
	{
		mpi_free(pmpiRR);
		polarssl_free(pmpiRR);
		pmpiRR = 0;
	}
	if (ptSG)
	{
		ecp_point_free(ptSG);
		polarssl_free(ptSG);
		ptSG = 0;
	}
	if (ptTP)
	{
		ecp_point_free(ptTP);
		polarssl_free(ptTP);
		ptTP = 0;
	}
	if (ptPoint)
	{
		ecp_point_free(ptPoint);
		polarssl_free(ptPoint);
		ptPoint = 0;
	}

	return iRtn;
}

