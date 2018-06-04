#ifndef HEADER_mtx_UTIL_H
#define HEADER_mtx_UTIL_H

#include "./polarssl/ecp.h"

#ifdef  __cplusplus
extern "C" {
#endif

//#define _mtx_OLD_VERSION

//Assertion
#define mtx_ASSERT_EQ(_rtn,_val) \
	do\
	{\
		if((_rtn)!=(_val))\
		{\
			goto END;\
		}\
	} while(0)

#define mtx_ASSERT_EQ_EX(_rtn,_val,_err_num) \
	do\
	{\
		if((_rtn)!=(_val))\
		{\
			iRtn=(_err_num);\
			goto END;\
		}\
	} while(0)

#define mtx_ASSERT_NEQ(_rtn,_val) \
	do\
	{\
		if((_rtn)==(_val))\
		{\
			goto END;\
		}\
	} while(0)

#define mtx_ASSERT_NEQ_EX(_rtn,_val,_err_num) \
	do\
	{\
		if((_rtn)==(_val))\
		{\
			iRtn=(_err_num);\
			goto END;\
		}\
	} while(0)

typedef unsigned int mtxu32;

typedef struct _mtx_keypair
{
	ecp_group grp;      /*!<  elliptic curve used           */
	mpi d;              /*!<  secret signature key          */
	ecp_point Q;        /*!<  public signature key          */
} mtx_keypair;

#define ECPARAMS    POLARSSL_SM2_256

int LittleEndianCheck(void);// is little endian
void reverseData(unsigned char* pbData, unsigned int uiDataLen);
void xorData(unsigned char *out, const unsigned char * const input1, const unsigned char * const input2, const long length);
void andData(unsigned char *out, const unsigned char * const input1, const unsigned char * const input2, const long length);
void orData(unsigned char *out, const unsigned char * const input1, const unsigned char * const input2, const long length);
int mtx_KDF(const unsigned char *pbZValue, unsigned int uiZLen, unsigned char *pbK, unsigned int uiKLen, mtxu32 uiCTInit);
int mtx_initKeyPair(mtx_keypair *pmtxKeyPair);
int mtx_freeKeyPair(mtx_keypair *pmtxKeyPair);
int mtx_genKeyPair(mtx_keypair *pmtxKeyPair);
int mtx_genKeyPairEx(mtx_keypair *pmtxKeyPair, unsigned char *priKey);
void mtx_getPubKey(unsigned char *pubKey, unsigned char *priKey);
int mtx_getHashValue(const unsigned char *msg, int msgLen, unsigned char *pbHash, mtx_keypair *eckey);
mtx_keypair* mtxCreateKeyContext();

#ifdef __cplusplus
}
#endif

#endif