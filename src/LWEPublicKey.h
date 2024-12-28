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
 * LWEPublicKey.h
 *
 *  Created on: 12.08.2011
 */

#ifndef LWEPUBLICKEY_H_
#define LWEPUBLICKEY_H_

/* NTL library for big integers */
#include <NTL/ZZ_pE.h>

NTL_CLIENT

/**
 * Class for a LWE public key. This class stores
 * a public key of the LWE cryptosystem.
 */
class LWEPublicKey {
public:
	/**
	 * Constructs empty LWEPublicKey object.
	 */
	LWEPublicKey(void);

	/**
	 * Constructs LWEPublicKey object with given polynomials a and p.
	 * \param a Uniform random polynomial in R_q
	 * \param p Per user public polynomial
	 */
	LWEPublicKey(ZZ_pE a, ZZ_pE p);

	virtual ~LWEPublicKey();

	/**
	 * Getter for polynomial a.
	 * \return Pointer to polynomial a
	 */
	ZZ_pE* getA();

	/**
	 * Getter for polynomial p.
	 * \return Pointer to polynomial p
	 */
	ZZ_pE* getP();

	/**
	 * Setter for polynomial a.
	 * \param a Uniform random polynomial in R_q
	 */
	void setA(ZZ_pE a);

	/**
	 * Setter for polynomial p.
	 * \param p Per user public polynomial p
	 */
	void setP(ZZ_pE p);

private:
	ZZ_pE a, /*!< Uniform random polynomial in R_q */
		  p; /*!< Per user public polynomial */

};

/* Global operators */

/**
 * Reads public key from stream.
 * \param stream Input stream
 * \param key Pointer to a LWEPublicKey object
 * \return Updated stream
 */
istream& operator>>(istream& stream, LWEPublicKey *key);

/**
 * Writes public key to stream.
 * \param stream Output stream
 * \param key Pointer to a LWEPublicKey object
 * \return Updated stream
 */
ostream& operator<<(ostream& stream, LWEPublicKey& key);

#endif /* LWEPUBLICKEY_H_ */
