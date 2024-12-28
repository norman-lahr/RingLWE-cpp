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
 * LWEKeypair.h
 *
 *  Created on: 12.08.2011
 */

#ifndef LWEKEYPAIR_H_
#define LWEKEYPAIR_H_

#include "Sampler.h"
#include "LWEPublicKey.h"
#include "LWEPrivateKey.h"
#include "Parameters.h"


/**
 * Class that represents a keypair. This class stores
 * a pair of keys. It allows generating a new public
 * and a new private key for the LWE cryptosystem.
 */
class LWEKeypair {
public:
	/**
	 * Builds a new keypair with the given parameters.
	 * \param parameters Parameters object
	 */
	LWEKeypair(Parameters *parameters);

	/**
	 * Builds a new keypair with given public and private key.
	 * \param publicKey LWEPublicKey object
	 * \param privateKey LWEPrivateKey object
	 */
	LWEKeypair(LWEPublicKey *publicKey, LWEPrivateKey *privateKey);

	/**
	 * Deletes key objects.
	 */
	virtual ~LWEKeypair();

	/**
	 * Getter for public key.
	 * \return LWEPublicKey object
	 */
	LWEPublicKey* getPublicKey();

	/**
	 * Getter for private key.
	 * \return LWEPrivateKey object
	 */
	LWEPrivateKey* getPrivateKey();

private:
	LWEPublicKey *publicKey; /*!< Public key object */
	LWEPrivateKey *privateKey; /*!< Private key object */

};

#endif /* LWEKEYPAIR_H_ */
