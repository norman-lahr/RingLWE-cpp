/*
 * LWE-Polynomial -- Learning-With-Errors-based Encryption System --
 * Copyright (C) 2011 Norman Lahr

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.

 * Contact: norman@lahr.email

 * Refer to the file LICENSE for the details of the GPL.
 *
 * LWE.h
 *
 *  Created on: 12.08.2011
 */

#ifndef LWE_H_
#define LWE_H_

#include <math.h>
#include <fstream>
/* NTL library for big integers */
#include <NTL/mat_ZZ.h>
#include "LWEPublicKey.h"
#include "LWEPrivateKey.h"
#include "Sampler.h"
#include "Parameters.h"

NTL_CLIENT

/**
 * Class for an LWE crypto-token. This class
 * enables encryption and decryption of single
 * data blocks and also of hole files.
 */
class LWE {
public:
	/**
	 * Create new LWE with given parameters.
	 * \param parameters Parameters object
	 */
	LWE(Parameters *parameters);

	virtual ~LWE();

	/**
	 * Encrypts the hole plaintext with the given public key.
	 * The function writes every encrypted block of data
	 * directly to file, because of memory issues with large
	 * plaintexts. The file is the one, which is stored in the
	 * parameters object.
	 * \param key LWEPublicKey object
	 */
	void encrypt(LWEPublicKey *key);

	/**
	 * Decrypts the hole ciphertext file with the given private key.
	 * The function writes every decrypted block of data
	 * directly to file, because of memory issues with large
	 * ciphertexts. The file is the one, which is stored in the
	 * parameters object.
	 * \param key LWEPrivateKey object
	 */
	void decrypt(LWEPrivateKey *key);

private:
	Parameters *parameters; /*!< Stores parameters for the crypto-sytem and also input/output filenames */

	Sampler *sampler; /*!< Stores the sampler for the encryption */

	/**
	 * Encrypts a plaintext block (length l) with given public key.
	 * \param key LWEPublicKey object
	 * \param plaintext Points to the begin of the plaintext block
	 * \return Ciphertext represented by a Polynomial in ring R_q
	 */
	ZZ_pE* encryptBlock(LWEPublicKey *key, char *plaintext);

	/**
	 * Decrypts a ciphertext block with given private key.
	 * \param key LWEPrivateKey object
	 * \param ciphertext Points to a polynomial in ring R_q
	 * \return Plaintext in char/byte representation
	 */
	char* decryptBlock(LWEPrivateKey *key, ZZ_pE *ciphertext);

	/**
	 * Transforms a Bit-Vector to a polynomial in R_q.
	 * \param Plaintext block of length l
	 * \return Polynomial in R_q representation of the given data block
	 */
	ZZ_pE* encode(char* msg);

	/**
	 * Transforms a polynomial in R_q back to Bit-Vector.
	 * \param Plaintext as a polynomial in R_q with errors
	 * \return Error corrected plaintext block
	 */
	char* decode(ZZ_pE *msg);

	/**
	 * Reads a file.
	 * \param name Filename
	 * \param length Return value for the length of the char array
	 * \return Content of the file
	 */
	char* readFile(char *name, unsigned long int *length);

};

#endif /* LWE_H_ */
