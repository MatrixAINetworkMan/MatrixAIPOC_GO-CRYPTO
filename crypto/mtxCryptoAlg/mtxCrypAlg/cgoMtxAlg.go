// Copyright 2018 The Matrix Authors
// This file is part of the Matrix library.
//
// The Matrix library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Matrix library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Matrix library. If not, see <http://www.gnu.org/licenses/>.

package mtxCrypAlg

// #include <stdio.h>
// #include <stdlib.h>
// #include "./mtxHash/mtxHash.h"
// #include "./mtxHash/mtxHash.c"
//#include "./mtxEcdsa/mtx.h"
//#include "./mtxEcdsa/mtx_util.h"
//#include "./mtxEcdsa/mtx_util.c"
import "C"

import (
	"unsafe"
	"crypto/ecdsa"
)


func CgoSign(msg []byte, prv *ecdsa.PrivateKey) ([]byte) {
	var keypaircontext *C.mtx_keypair
	keypaircontext = C.mtxCreateKeyContext()
	C.mtx_initKeyPair(keypaircontext)

	priKey := prv.D.Bytes()
	priKeydata := (*C.uchar)(unsafe.Pointer(&priKey[0]))
	C.mtx_genKeyPairEx(keypaircontext, priKeydata)

	res := C._mtx_sign_size(keypaircontext)
	if res > 0 {
		//fmt.Printf("秘钥类型正确\n")
	} else {
		return nil
	}

	var retlen C.uint
	retlen = 100
	msglen := (C.uint)(len(msg))
	var ret = make([]byte, 65)
	dataret := (*C.uchar)(unsafe.Pointer(&ret[0]))
	msgdata := (*C.uchar)(unsafe.Pointer(&msg[0]))
	C.mtx_sign(msgdata, msglen, dataret, &retlen, keypaircontext)
	C.mtx_freeKeyPair(keypaircontext)
	keypaircontext = nil

	if retlen == 0 {
		return nil
	} else {
		ret[64] = 1;
		return []byte(ret)
	}
}

func memcpy(dst, src []byte, size int) {
	for i := 0; i < size; i++ {
		dst[i] = src[i]
	}
	return
}

func CgoVerifySig(msg []byte, sig []byte, pubKey []byte) (bool) {
	var keypaircontext *C.mtx_keypair
	keypaircontext = C.mtxCreateKeyContext()
	C.mtx_initKeyPair(keypaircontext)
	C.mtx_genKeyPair(keypaircontext)

	var pubKeyX1 = make([]byte, 32)
	memcpy(pubKeyX1, pubKey[1:], 32)
	pubKeyX2 := (*C.uchar)(unsafe.Pointer(&pubKeyX1[0]))
	//tmpiX := new(C.mpi)
	tmpiX := keypaircontext.Q.X
	getX := (*C.mpi)(unsafe.Pointer(&tmpiX))
	C.mpi_read_binary(getX, pubKeyX2, (C.size_t)(len(pubKeyX1)))
	//keypaircontext.Q.X = *tmpiX

	var pubKeyY1 = make([]byte, 32)
	memcpy(pubKeyY1, pubKey[33:], 32)
	pubKeyY2 := (*C.uchar)(unsafe.Pointer(&pubKeyY1[0]))
	//tmpiY := new(C.mpi)
	tmpiY := keypaircontext.Q.Y
	getY := (*C.mpi)(unsafe.Pointer(&tmpiY))
	C.mpi_read_binary(getY, pubKeyY2, (C.size_t)(len(pubKeyY1)))
	//keypaircontext.Q.Y = *tmpiY

	res := C._mtx_sign_size(keypaircontext)
	if res > 0 {
		//fmt.Printf("秘钥类型正确\n")
	} else {
		return false
	}

	msglen := (C.uint)(len(msg))
	datasig := (*C.uchar)(unsafe.Pointer(&sig[0]))
	msgdata := (*C.uchar)(unsafe.Pointer(&msg[0]))

	ret := C.mtx_verify(msgdata, msglen, datasig, 64, keypaircontext)
	C.mtx_freeKeyPair(keypaircontext)
	keypaircontext = nil

	if ret == 1 {
		return true
	} else {
		return false
	}
}

func CgoEncrypt(msg []byte, pubKey []byte) ([]byte) {
	var keypaircontext *C.mtx_keypair
	keypaircontext = C.mtxCreateKeyContext()
	C.mtx_initKeyPair(keypaircontext)
	C.mtx_genKeyPair(keypaircontext)

	var pubKeyX1 = make([]byte, 32)
	memcpy(pubKeyX1, pubKey[1:], 32)
	pubKeyX2 := (*C.uchar)(unsafe.Pointer(&pubKeyX1[0]))
	tmpiX := keypaircontext.Q.X
	getX := (*C.mpi)(unsafe.Pointer(&tmpiX))
	C.mpi_read_binary(getX, pubKeyX2, (C.size_t)(len(pubKeyX1)))

	var pubKeyY1 = make([]byte, 32)
	memcpy(pubKeyY1, pubKey[33:], 32)
	pubKeyY2 := (*C.uchar)(unsafe.Pointer(&pubKeyY1[0]))
	tmpiY := keypaircontext.Q.Y
	getY := (*C.mpi)(unsafe.Pointer(&tmpiY))
	C.mpi_read_binary(getY, pubKeyY2, (C.size_t)(len(pubKeyY1)))

	msglen := (C.uint)(len(msg))
	res := C._mtx_encrypt_size(keypaircontext, msglen)
	if res > 0 {
		//fmt.Printf("秘钥类型正确\n")
	} else {
		return nil
	}

	var retlen C.uint
	retlen = 100
	var ret = make([]byte, 96 + msglen)
	dataret := (*C.uchar)(unsafe.Pointer(&ret[0]))
	msgdata := (*C.uchar)(unsafe.Pointer(&msg[0]))
	C.mtx_encrypt(msgdata, msglen, dataret, &retlen, keypaircontext)
	C.mtx_freeKeyPair(keypaircontext)
	keypaircontext = nil

	if retlen == 0 {
		return nil
	} else {
		return []byte(ret)
	}
}

func CgoDecrypt(cipher []byte, prv *ecdsa.PrivateKey) ([]byte) {
	var keypaircontext *C.mtx_keypair
	keypaircontext = C.mtxCreateKeyContext()
	C.mtx_initKeyPair(keypaircontext)

	priKey := prv.D.Bytes()
	pKey := (*C.uchar)(unsafe.Pointer(&priKey[0]))
	C.mtx_genKeyPairEx(keypaircontext, pKey)

	cipherlen := (C.uint)(len(cipher))
	var retlen C.uint
	retlen = 100
	var ret = make([]byte, cipherlen-96)
	dataret := (*C.uchar)(unsafe.Pointer(&ret[0]))
	cipherdata := (*C.uchar)(unsafe.Pointer(&cipher[0]))
	C.mtx_decrypt(cipherdata, cipherlen, dataret, &retlen, keypaircontext)
	C.mtx_freeKeyPair(keypaircontext)
	keypaircontext = nil

	if retlen == 0 {
		return nil
	} else {
		return []byte(ret)
	}
}

func CgoHash(msg []byte) ([]byte) {
	var retlen C.uint
	retlen = 100
	msglen := (C.uint)(len(msg))

	var ret = make([]byte, 32)
	dataret := (*C.uchar)(unsafe.Pointer(&ret[0]))
	msgdata := (*C.uchar)(unsafe.Pointer(&msg[0]))
	C.mtx_hash(msgdata, msglen, dataret, &retlen)

	if retlen == 0 {
		return nil
	} else {
		return []byte(ret)
	}
}

func CgoGetPubKey(prv *ecdsa.PrivateKey) ([]byte) {
	priKey := prv.D.Bytes()
	pKey := (*C.uchar)(unsafe.Pointer(&priKey[0]))
	var pubKey = make([]byte, 65)
	pubKeydata := (*C.uchar)(unsafe.Pointer(&pubKey[0]))
	C.mtx_getPubKey(pubKeydata, pKey)

	return pubKey
}

func CgoGetHashValue(msg []byte, prv *ecdsa.PrivateKey) ([]byte) {
	var keypaircontext *C.mtx_keypair
	keypaircontext = C.mtxCreateKeyContext()
	C.mtx_initKeyPair(keypaircontext)

	priKey := prv.D.Bytes()
	pKey := (*C.uchar)(unsafe.Pointer(&priKey[0]))
	C.mtx_genKeyPairEx(keypaircontext, pKey)

	msglen := (C.int)(len(msg))
	var hValue = make([]byte, 32)
	HashValue := (*C.uchar)(unsafe.Pointer(&hValue[0]))
	msgdata := (*C.uchar)(unsafe.Pointer(&msg[0]))
	C.mtx_getHashValue(msgdata, msglen, HashValue, keypaircontext)
	C.mtx_freeKeyPair(keypaircontext)
	keypaircontext = nil

	return hValue
}
