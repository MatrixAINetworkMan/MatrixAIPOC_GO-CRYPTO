#ifndef HEADER_mtxHash_H
#define HEADER_mtxHash_H

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef unsigned long u32m3;
typedef unsigned char u8m3;

#define mtxHash_DIGEST_LENGTH 32
#define mtxHash_CBLOCK	64

//mtxHash Flag值
#define mtxHash_FLAG_NEED_CALC_ZVALUE 0x1

typedef struct _mtxHash_CTX
{
	u8m3	m_pbLastGroup[mtxHash_CBLOCK];
	u32m3	m_dwLastLen;
	u32m3	m_dwGroupNum; //已经计算过的分组数目
	u32m3	m_AA;
	u32m3   m_BB;
	u32m3	m_CC;
	u32m3   m_DD;
	u32m3	m_EE;
	u32m3   m_FF;
	u32m3	m_GG;
	u32m3   m_HH;

	u8m3	m_ucFlag;
}mtxHash_CTX;

int mtxHash_INIT(mtxHash_CTX* pmtxHashCtx);

int mtxHash_UPDATE(mtxHash_CTX* pmtxHashCtx,
					 u8m3* pbData, 
					 u32m3 dwDataLen);

int mtxHash_FINAL(u8m3* pbHashValue,
	mtxHash_CTX* pmtxHashCtx);

/*
* computes hash
* \param bHashData: to be hash messages
* \param bHashDatalen: message length to be hash
* \param pbHashRet: buffer to hold the hash Result
* \param pbHashRetlen: the length of the hash Result
* \return void
*/
void mtx_hash(unsigned char *bHashData, unsigned int bHashDatalen, unsigned char *pbHashRet, unsigned int *pbHashRetlen);

int mtxHash_GETSTATE(mtxHash_CTX*	pmtxHashCtx, u8m3* iv, u8m3* lastData, int* lastDataLen, int64_t *bitsHashProcessed);

#ifdef  __cplusplus
}
#endif

#endif