## Introduction

This is Matrix's GO implementations on Crypto for POC. It can only be considered as a functional test based on Ethereum crypto algorithm instead of Matrix's final crypto implementation.

Details as follows:

1. mtxCrypAlg under crypto contains main implementations of crypto algorithms, and mtxcrypto.go is the interface provided for external calling;

2. polarssl under mtxCrypAlg are third-party library header files; mtxEcdsa contains header files for Encryption and Secryption, as well as signature verification; mtxHash contains HASH implementations;

3. .c file under mtxCrypAlg are library implementations and algorithms; cgoMtxAlg.go enables the translation between GO and C using CGO;

4. signature_cgo.go and crypto.go under crypto are ethereum's original crypto algorithm interface files for external calling, and based on this, we introduced two more interfaces SignEx and VerifySignatureEx which will be used for signature verification. Ecrecover and EcrecoverEx interfaces supports public key recovery. generateKeyEx is the new interface for publick/private key generation