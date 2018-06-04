#include <string.h>
#include <time.h>

#include "../mtxHash/mtxHash.h"
#include "mtx_util.h"

#include "mtx.h"//just to execute

#if defined(POLARSSL_PLATFORM_C)
#include "../polarssl/platform.h"
#else
#include <stdlib.h>
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#include "../polarssl/hmac_drbg.h"

mtx_keypair* mtxCreateKeyContext()
{
    mtx_keypair	*eckey_r_tmp = NULL;
    eckey_r_tmp = (mtx_keypair *)polarssl_malloc(sizeof(mtx_keypair));
    return eckey_r_tmp;
}

int LittleEndianCheck(void)// is little endian
{
	unsigned int i = 0x12;

	if (*((unsigned char*)(&i)) == 0)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

void reverseData(unsigned char* pbData, unsigned int uiDataLen)
{
	unsigned int i = 0;

	if (!pbData)
	{
		return;
	}

	for (i=0; i<uiDataLen/2; i++)
	{
		pbData[i] = pbData[i] ^ pbData[uiDataLen-i-1];
		pbData[uiDataLen-i-1] = pbData[i] ^ pbData[uiDataLen-i-1];
		pbData[i] = pbData[i] ^ pbData[uiDataLen-i-1];
	}
}

void xorData(unsigned char *out, const unsigned char * const input1, const unsigned char * const input2, const long length)
{
	long i = 0;

	for (i=0; i<length; i++)
	{
		out[i] = input1[i] ^ input2[i];
	}
}

void andData(unsigned char *out, const unsigned char * const input1, const unsigned char * const input2, const long length)
{
	long i = 0;

	for (i=0; i<length; i++)
	{
		out[i] = input1[i] & input2[i];
	}
}

void orData(unsigned char *out, const unsigned char * const input1, const unsigned char * const input2, const long length)
{
	long i = 0;

	for (i=0; i<length; i++)
	{
		out[i] = input1[i] | input2[i];
	}
}


int mtx_KDF(const unsigned char *pbZValue, unsigned int uiZLen, unsigned char *pbK, unsigned int uiKLen, mtxu32 uiCTInit)
{
	int iRtn = 0;

	int	iLE = 0;
	mtxHash_CTX	mtxHashctx;
	mtxu32	uiCT = 0;
	unsigned char	*pbMsg = NULL;
	unsigned int	uiMsgLen = 0;
	unsigned char	pbFinalHash[mtxHash_DIGEST_LENGTH] = {0};

	unsigned int	uiLoopCount = 0, uiFinalCount = 0, i = 0;

	mtx_ASSERT_NEQ_EX(pbK, 0, 0);
	mtx_ASSERT_EQ_EX(sizeof(mtxu32), 4, 0);

	if (!pbZValue)
	{
		uiZLen = 0;
	}
	uiMsgLen = uiZLen + 4;// Z || xx xx xx xx
	pbMsg = (unsigned char*)polarssl_malloc(uiMsgLen);
	mtx_ASSERT_NEQ_EX(pbMsg, 0, 0);
	memcpy(pbMsg, pbZValue, uiZLen);

	uiLoopCount = uiKLen / mtxHash_DIGEST_LENGTH;
	uiFinalCount = uiKLen % mtxHash_DIGEST_LENGTH;
	iLE = LittleEndianCheck();
	uiCT=uiCTInit;
	if (iLE)
	{
		for (i=0; i<uiLoopCount; i++)
		{
			memcpy(pbMsg+uiZLen, (unsigned char*)(&uiCT), 4);
			reverseData(pbMsg+uiZLen, 4);

			mtxHash_INIT(&mtxHashctx);
			mtxHash_UPDATE(&mtxHashctx, pbMsg, uiMsgLen);
			mtxHash_FINAL(pbK, &mtxHashctx);
			pbK += mtxHash_DIGEST_LENGTH;
			uiCT++;
		}
		if (uiFinalCount)
		{
			memcpy(pbMsg+uiZLen, (unsigned char*)(&uiCT), 4);
			reverseData(pbMsg+uiZLen, 4);

			mtxHash_INIT(&mtxHashctx);
			mtxHash_UPDATE(&mtxHashctx, pbMsg, uiMsgLen);
			mtxHash_FINAL(pbFinalHash, &mtxHashctx);
			memcpy(pbK, pbFinalHash, uiFinalCount);
		}
	}
	else
	{
		for (i=0; i<uiLoopCount; i++)
		{
			memcpy(pbMsg+uiZLen, ((unsigned char*)(&uiCT) + sizeof(uiCT) -4), 4);

			mtxHash_INIT(&mtxHashctx);
			mtxHash_UPDATE(&mtxHashctx, pbMsg, uiMsgLen);
			mtxHash_FINAL(pbK, &mtxHashctx);
			pbK += mtxHash_DIGEST_LENGTH;
			uiCT++;
		}
		if (uiFinalCount)
		{
			memcpy(pbMsg+uiZLen, ((unsigned char*)(&uiCT) + sizeof(uiCT) -4), 4);

			mtxHash_INIT(&mtxHashctx);
			mtxHash_UPDATE(&mtxHashctx, pbMsg, uiMsgLen);
			mtxHash_FINAL(pbFinalHash, &mtxHashctx);
			memcpy(pbK, pbFinalHash, uiFinalCount);
		}
	}

	iRtn = 1;
END:
	if (pbMsg)
	{
		polarssl_free(pbMsg);
		pbMsg = NULL;
	}

	return iRtn;
}


int mtx_initKeyPair(mtx_keypair *pmtxKeyPair)
{
	int iRtn = -1;

	mtx_ASSERT_NEQ_EX(pmtxKeyPair, 0, 0);

	ecp_group_init(&pmtxKeyPair->grp);
	mpi_init(&pmtxKeyPair->d);
	ecp_point_init(&pmtxKeyPair->Q);

	iRtn = 1;
END:
	return iRtn;
}

int mtx_freeKeyPair(mtx_keypair *pmtxKeyPair)
{
	int iRtn = -1;

	mtx_ASSERT_NEQ_EX(pmtxKeyPair, 0, 0);

	ecp_group_free(&pmtxKeyPair->grp);
	mpi_free(&pmtxKeyPair->d);
	ecp_point_free(&pmtxKeyPair->Q);

	iRtn = 1;
END:
	return iRtn;
}

int mtx_genKeyPair(mtx_keypair *pmtxKeyPair)
{
	int iRtn = -1;

	hmac_drbg_context *rng_ctx = 0;
	const md_info_t *md_info = 0;

	mtx_ASSERT_NEQ_EX(pmtxKeyPair, 0, 0);

	iRtn = ecp_use_known_dp(&pmtxKeyPair->grp, ECPARAMS);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	md_info = md_info_from_type(POLARSSL_MD_SHA256);
	mtx_ASSERT_NEQ_EX(md_info, 0, 0);
	rng_ctx = (hmac_drbg_context*)polarssl_malloc(sizeof(hmac_drbg_context));
	mtx_ASSERT_NEQ_EX(rng_ctx, 0, 0);
	iRtn = hmac_drbg_init(rng_ctx, md_info, mtx_rand, 0, 0, 0);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	iRtn = ecp_gen_keypair(&pmtxKeyPair->grp, &pmtxKeyPair->d, &pmtxKeyPair->Q, hmac_drbg_random, rng_ctx);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	iRtn = 1;
END:
	if (rng_ctx)
	{
		hmac_drbg_free(rng_ctx);
		free(rng_ctx);
		rng_ctx = 0;
	}
	
	return iRtn;
}

int mtx_genKeyPairEx(mtx_keypair *pmtxKeyPair, unsigned char *priKey)
{
	int iRtn = -1;

	hmac_drbg_context *rng_ctx = 0;
	const md_info_t *md_info = 0;

	mtx_ASSERT_NEQ_EX(pmtxKeyPair, 0, 0);

	iRtn = ecp_use_known_dp(&pmtxKeyPair->grp, ECPARAMS);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	md_info = md_info_from_type(POLARSSL_MD_SHA256);
	mtx_ASSERT_NEQ_EX(md_info, 0, 0);
	rng_ctx = (hmac_drbg_context*)polarssl_malloc(sizeof(hmac_drbg_context));
	mtx_ASSERT_NEQ_EX(rng_ctx, 0, 0);
	iRtn = hmac_drbg_init(rng_ctx, md_info, mtx_rand, 0, 0, 0);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	mpi_read_binary(&pmtxKeyPair->d, priKey, 32);
	iRtn = ecp_gen_keypairEx(&pmtxKeyPair->grp, &pmtxKeyPair->d, &pmtxKeyPair->Q, NULL, NULL);
	mtx_ASSERT_EQ_EX(iRtn, 0, 0);

	iRtn = 1;
END:
	if (rng_ctx)
	{
		hmac_drbg_free(rng_ctx);
		free(rng_ctx);
		rng_ctx = 0;
	}

	return iRtn;
}

void mtx_getPubKey(unsigned char *pubKey, unsigned char *priKey)
{
	if (priKey == NULL || pubKey == NULL)
	{
		return;
	}
	unsigned char tempData[32] = {0};
	mtx_keypair pmtxKeyPair;
	mtx_initKeyPair(&pmtxKeyPair);
	mtx_genKeyPairEx(&pmtxKeyPair, priKey);
	mpi_write_binary(&pmtxKeyPair.Q.X, tempData, 32);
	pubKey[0] = 4;
	memcpy(pubKey+1, tempData, 32);
	mpi_write_binary(&pmtxKeyPair.Q.Y, tempData, 32);
	memcpy(pubKey+33, tempData, 32);
}

int mtx_getHashValue(const unsigned char *msg, int msgLen, unsigned char *pbHash, mtx_keypair *eckey)
{
	int iRtn = 0;
	unsigned int	uiZLen = 0;
	unsigned char	*pbMsg = NULL;
	unsigned int	uiMsgLen = 0;
	mtxHash_CTX	mtxHashctx;

	uiMsgLen = mtxHash_DIGEST_LENGTH/*ZLen*/ + msgLen;
	pbMsg = (unsigned char *)polarssl_malloc(uiMsgLen);
	//ID
	unsigned char pbID[18] = {0x41, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33, 0x40, 0x59, 0x41, 0x48, 0x4F, 0x4F, 0x2E, 0x43, 0x4F, 0x4D};
	//calc Z
	iRtn = mtx_getZ(pbID, sizeof(pbID), pbMsg, &uiZLen, eckey);
	//cat the Z||m as the final message
	memcpy(pbMsg + uiZLen, msg, msgLen);
	//calc e
	mtxHash_INIT(&mtxHashctx);
	mtxHash_UPDATE(&mtxHashctx, (unsigned char*)pbMsg, uiMsgLen);
	mtxHash_FINAL(pbHash, &mtxHashctx);

	return 32;
}