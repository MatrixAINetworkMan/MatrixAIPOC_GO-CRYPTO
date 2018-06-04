#include "mtxHash.h"
#include <string.h>
#include <stdint.h>

#define u32m3_2_u8m3(dwValue, pbBuffer) { (pbBuffer)[3] = (u8m3)(dwValue), \
											(pbBuffer)[2] = (u8m3)((dwValue)>>8); \
											(pbBuffer)[1] = (u8m3)((dwValue)>>16); \
											(pbBuffer)[0] = (u8m3)((dwValue)>>24); }

#define T0 (0x79cc4519)
#define T1 (0x7a879d8a)
#define FF0(X, Y, Z) ( (X) ^ (Y) ^ (Z) )
#define FF1(X, Y, Z) ( ((X)&(Y)) | ((X)&(Z)) | ((Y)&(Z)) )
#define GG0(X, Y, Z) ( (X) ^ (Y) ^ (Z) )
#define GG1(X, Y, Z) ( ((X)&(Y)) | ((~(X))&(Z)) )
#define ROL(X, cnt)  ( ( (X)<<((cnt)&31) ) | ( (X)>>(32-((cnt)&31)) ) )
#define P0(X)		 ( (X) ^ ROL(X,  9) ^ ROL(X, 17))
#define P1(X)		 ( (X) ^ ROL(X, 15) ^ ROL(X, 23))

static int ProcessOneGroup(u8m3 *pbData, mtxHash_CTX* pmtxHashCtx);

int mtxHash_INIT(mtxHash_CTX* pmtxHashCtx)
{
	pmtxHashCtx->m_dwLastLen = 0x00;
	pmtxHashCtx->m_dwGroupNum = 0x00;
	pmtxHashCtx->m_AA = 0x7380166f;
	pmtxHashCtx->m_BB = 0x4914b2b9;
	pmtxHashCtx->m_CC = 0x172442d7;
	pmtxHashCtx->m_DD = 0xda8a0600;
	pmtxHashCtx->m_EE = 0xa96f30bc;
	pmtxHashCtx->m_FF = 0x163138aa;
	pmtxHashCtx->m_GG = 0xe38dee4d;
	pmtxHashCtx->m_HH = 0xb0fb0e4e;

	return 1;
}

int mtxHash_UPDATE(mtxHash_CTX*	pmtxHashCtx,
					 u8m3*			pbData, 
					 u32m3			dwDataLen)
{
	if ( (dwDataLen + pmtxHashCtx->m_dwLastLen) < 0x40 )
	{
		memcpy(pmtxHashCtx->m_pbLastGroup + pmtxHashCtx->m_dwLastLen, pbData, dwDataLen);
		pmtxHashCtx->m_dwLastLen += dwDataLen;
	}
	else 
	{
		u32m3 dwCopyLen;
		dwCopyLen = 0x40 - pmtxHashCtx->m_dwLastLen;
		memcpy(pmtxHashCtx->m_pbLastGroup + pmtxHashCtx->m_dwLastLen, pbData, dwCopyLen);
		pbData += dwCopyLen;
		dwDataLen -= dwCopyLen;
		ProcessOneGroup(pmtxHashCtx->m_pbLastGroup, pmtxHashCtx);
		pmtxHashCtx->m_dwGroupNum++;

		while ( dwDataLen >= 0x40 )
		{
			ProcessOneGroup(pbData, pmtxHashCtx);
			dwDataLen -= 0x40;
			pbData += 0x40;
			pmtxHashCtx->m_dwGroupNum++;
		}
		memcpy(pmtxHashCtx->m_pbLastGroup, pbData, dwDataLen);
		pmtxHashCtx->m_dwLastLen = dwDataLen;
	}
	return 1;
}

/** 
* ��ȡ��ǰmtxHash������м�״̬���õ�����IV��ʣ��δ�������ݡ�
* ��������Ҫ��֤����iv���ڴ��С��С��32�ֽڣ�lastData���ڴ��С��С��63���ֽڡ�
*@param [in] pmtxHashCtx �����ľ��
*@param [out] iv IV�ĵ�ǰֵ���̶�Ϊ32���ֽ�
*@param [out] lastData ʣ���δ������������ݣ������Ϊ63���ֽ�
*@param [out] lastDataLen ʣ���δ������������ݳ��ȣ�ֵ���Ϊ63
*/
int mtxHash_GETSTATE(mtxHash_CTX*	pmtxHashCtx, u8m3* iv, u8m3* lastData, int* lastDataLen, int64_t *bitsHashProcessed)
{
	u8m3 *pbHashValue = 0;
	*lastDataLen = pmtxHashCtx->m_dwLastLen;
	memcpy(lastData, pmtxHashCtx->m_pbLastGroup, pmtxHashCtx->m_dwLastLen);
	
	pbHashValue = iv;
	u32m3_2_u8m3(pmtxHashCtx->m_AA, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_BB, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_CC, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_DD, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_EE, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_FF, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_GG, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_HH, pbHashValue);

	*bitsHashProcessed = pmtxHashCtx->m_dwGroupNum * 64 * 8;
	return 1;
}

int mtxHash_FINAL(u8m3*		pbHashValue,
				  mtxHash_CTX* pmtxHashCtx)
{
	u8m3	pbLastGroup[0x40*2];
	u32m3	dwLastLen;
	u32m3	dwDataLen;
	u32m3	dwOffset;

	dwLastLen = pmtxHashCtx->m_dwLastLen;
	if (dwLastLen>=56)
	{
		dwOffset = 0x40;
	}
	else
	{
		dwOffset = 0x00;
	}
	memset(pbLastGroup, 0x00, sizeof(pbLastGroup));
	memcpy(pbLastGroup, pmtxHashCtx->m_pbLastGroup, dwLastLen);
	pbLastGroup[dwLastLen] = 0x80;
	dwDataLen = pmtxHashCtx->m_dwGroupNum * 0x40 + dwLastLen;
	dwDataLen <<= 3;
	pbLastGroup[dwOffset+63] = (u8m3)(dwDataLen);
	pbLastGroup[dwOffset+62] = (u8m3)(dwDataLen>>8);
	pbLastGroup[dwOffset+61] = (u8m3)(dwDataLen>>16);
	pbLastGroup[dwOffset+60] = (u8m3)(dwDataLen>>24);

	ProcessOneGroup(pbLastGroup, pmtxHashCtx);

	if ( 0x40 == dwOffset )
	{
		ProcessOneGroup(pbLastGroup+0x40, pmtxHashCtx);
	}
	// 输出
	u32m3_2_u8m3(pmtxHashCtx->m_AA, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_BB, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_CC, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_DD, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_EE, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_FF, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_GG, pbHashValue);
	pbHashValue += 4;
	u32m3_2_u8m3(pmtxHashCtx->m_HH, pbHashValue);

	return 1;
}

static int ProcessOneGroup(u8m3 *pbData, mtxHash_CTX* pmtxHashCtx)
{
	u32m3 W[68], W_[64];
	u32m3 A, B, C, D, E, F, G, H;
	u32m3 SS1, SS2, TT1, TT2;
	int j;

	// 消息扩展
	for (j=0; j<16; j++)
	{
		W[j] = (pbData[j*4]<<24) | (pbData[j*4+1]<<16) | (pbData[j*4+2]<<8) | pbData[j*4+3];
	}
	for ( ; j<68; j++)
	{
		W[j] = P1(W[j-16]^W[j-9]^ROL(W[j-3], 15)) ^ ROL(W[j-13], 7) ^ W[j-6];
	}
	for (j=0; j<64; j++)
	{
		W_[j] = W[j] ^ W[j+4];
	}

	// 压缩函数
	A = pmtxHashCtx->m_AA;
	B = pmtxHashCtx->m_BB;
	C = pmtxHashCtx->m_CC;
	D = pmtxHashCtx->m_DD;
	E = pmtxHashCtx->m_EE;
	F = pmtxHashCtx->m_FF;
	G = pmtxHashCtx->m_GG;
	H = pmtxHashCtx->m_HH;
	for (j=0; j<16; j++)
	{
		SS1 = ROL(ROL(A, 12) + E + ROL(T0, j), 7);
		SS2 = SS1 ^ ROL(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W_[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROL(F, 19);
		F = E;
		E = P0(TT2);
	}
	for ( ; j<64; j++)
	{
		SS1 = ROL(ROL(A, 12) + E + ROL(T1, j), 7);
		SS2 = SS1 ^ ROL(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W_[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROL(F, 19);
		F = E;
		E = P0(TT2);
	}
	pmtxHashCtx->m_AA ^= A;
	pmtxHashCtx->m_BB ^= B;
	pmtxHashCtx->m_CC ^= C;
	pmtxHashCtx->m_DD ^= D;
	pmtxHashCtx->m_EE ^= E;
	pmtxHashCtx->m_FF ^= F;
	pmtxHashCtx->m_GG ^= G;
	pmtxHashCtx->m_HH ^= H;

	return 1;
}

void mtx_hash(unsigned char *bHashData, unsigned int bHashDatalen, unsigned char *pbHashRet, unsigned int *pbHashRetlen)
{
	mtxHash_CTX softmtxHash;
	memset(&softmtxHash, 0, sizeof(softmtxHash));
	mtxHash_INIT(&softmtxHash);
	mtxHash_UPDATE(&softmtxHash, bHashData, bHashDatalen);
	mtxHash_FINAL(pbHashRet, &softmtxHash);
	*pbHashRetlen = 32;
}
