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

package mtxCryptoAlg

import (
	"errors"
	"github.com/ethereum/go-ethereum/crypto/mtxCryptoAlg/mtxCrypAlg"
	"crypto/ecdsa"
)

var (
	ErrInvalidMsgLen       = errors.New("invalid message length, need 32 bytes")
	ErrInvalidSignatureLen = errors.New("invalid signature length")
	ErrInvalidRecoveryID   = errors.New("invalid signature recovery id")
	ErrInvalidKey          = errors.New("invalid private key")
	ErrInvalidPubkey       = errors.New("invalid public key")
	ErrSignFailed          = errors.New("signing failed")
	ErrRecoverFailed       = errors.New("recovery failed")
)

func Sign(hash []byte, prv *ecdsa.PrivateKey) ([]byte, error) {
	if prv == nil {
		return nil, ErrInvalidKey
	}

	sig := mtxCrypAlg.CgoSign(hash, prv)
	return sig, nil
}

func VerifySig(hash []byte, sig []byte, pubkey []byte) (bool) {
	if pubkey == nil || hash == nil || sig == nil {
		return false
	}
	return mtxCrypAlg.CgoVerifySig(hash, sig, pubkey)
}

func GetPubKey(prv *ecdsa.PrivateKey) ([]byte) {
	return mtxCrypAlg.CgoGetPubKey(prv)
}

func Hash(msg []byte) ([]byte) {
	if msg == nil {
		return nil
	}
	return mtxCrypAlg.CgoHash(msg)
}

func GetHashValue(msg []byte, prv *ecdsa.PrivateKey) ([]byte) {
	return mtxCrypAlg.CgoGetHashValue(msg, prv)
}

func Encrypt(msg []byte, prv []byte) ([]byte) {
	return mtxCrypAlg.CgoEncrypt(msg, prv)
}

func Decrypt(cipher []byte, prv *ecdsa.PrivateKey) ([]byte) {
	return mtxCrypAlg.CgoDecrypt(cipher, prv)
}
