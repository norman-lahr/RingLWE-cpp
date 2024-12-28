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
 * Parameters.h
 *
 *  Created on: 11.08.2011
 */

#ifndef PARAMETERS_H_
#define PARAMETERS_H_

/* For reading options from command line */
#include <getopt.h>

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <cstring>
#include <string>
#include <sstream>

#include <NTL/ZZX.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pEX.h>
#include <NTL/ZZ_pXFactoring.h>
NTL_CLIENT

#include "Constants.h"

using namespace std;

/**
 * Class for processing command line arguments.
 * This class reads out the command line
 * arguments and sets all relevant parameters
 * of the LWE cryptosystem.
 */
class Parameters {
public:
	/**
	 * Sets all parameters for the cryptosystem based on command line arguments.
	 * \param argc Argument count of command line
	 * \param argv Argument vector of command line
	 */
	Parameters(int argc,char *argv[]);

	/**
	 * Frees allocated memory.
	 */
	virtual ~Parameters();

	/**
	 * Getter for l.
	 */
	int getL();

	/**
	 * Getter for n.
	 */
	int getN();

	/**
	 * Getter for q.
	 */
	int getQ();

	/**
	 * Getter for s.
	 */
	float getS();

	/**
	 * Getter for delta.
	 */
	float getD();

	/**
	 * Getter for c.
	 */
	float getC();

	/**
	 * Getter for input plaintext filename.
	 */
	char* getINamePlaintext();

	/**
	 * Getter for input ciphertext filename.
	 */
	char* getINameCiphertext();

	/**
	 * Getter for output plaintext filename.
	 */
	char* getONamePlaintext();

	/**
	 * Getter for output ciphertext filename.
	 */
	char* getONameCiphertext();

	/**
	 * Getter for key filename.
	 */
	char* getNameKey();

	/**
	 * Getter for general output filename.
	 */
	char* getOutName();

	/**
	 * Getter for operation mode.
	 */
	int getOpMode();

	/**
	 * Getter for cryptosystem mode.
	 */
	int getMode();

	/**
	 * Getter for private key filename.
	 */
	string getNamePrivate();

	/**
	 * Getter for public key filename.
	 */
	string getNamePublic();

	/**
	 * Setter for input plaintext filename.
	 * \param iNamePlaintext Filename of the plaintext
	 */
    void setNamePlaintext(char *iNamePlaintext);

	/**
	 * Setter for input ciphertext filename.
	 * \param iNameCiphertext Filename of the ciphertext
	 */
    void setNameCiphertext(char *iNameCiphertext);

	/**
	 * Setter for key filename.
	 * \param iNameKey Filename of the key file
	 */
    void setNameKey(char *iNameKey);

	/**
	 * Setter for general output filename.
	 * \param outName Filename of the output file
	 */
    void setOutName(char *outName);

	/**
	 * Setter for operation mode.
	 * \param opMode Operation Mode (Gen, Enc, Dec)
	 */
    void setOpMode(int opMode = 0);

    /**
     * Setter for mode of the cryptosystem.
     * \param mode Choose a default set of parameters.
     */
    void setMode(int mode);

	/**
	 * Setter for cryptosystem's parameters.
	 */
    void setParameters();

    /**
     * Setter for parameter n.
     * \param n Parameter n
     */
    void setN(int n);

    /**
     * Setter for parameter q.
     * \param q Modulus q
     */
    void setQ(int q);

    /**
     * Setter for parameter l.
     * \param l Message length l
     */
    void setL(int l);

    /**
     * Setter for parameter s.
     * \param s Parameter s
     */
    void setS(float s);

    /**
     * Setter for delta.
     * \param d Parameter delta
     */
    void setD(float d);

    /**
     * Setter for parameter c.
     * \param c Parameter c
     */
    void setC(float c);

    /**
     * Getter for parameter plainLength.
     */
    bool getPlainLength();

private:

	int opMode; /*!< Registers what to do */

	int mode; /*!< Registers ciphermode */

	int n; 	/*!< Cryptosystem parameter n */
	int q; 	/*!< Cryptosystem parameter q */
	int l; 	/*!< Cryptosystem parameter l */
	float s; /*!< Cryptosystem parameter s */
	float d; /*!< Parameter delta, determining error probability */
	float c; /*!< Parameter c */

	/* Filenames */
	char *iNamePlaintext; 	/*!< input plaintext filename */
	char *iNameCiphertext; 	/*!< input ciphertext filename */
	char *iNameKey; 		/*!< input key filename */
	char *oNamePlaintext; 	/*!< output plaintext filename */
	char *oNameCiphertext; 	/*!< output ciphertext filename */
	char *outName; 			/*!< general output filename */

	string namePrivate; /*!< key filename with suffix "private" */
	string namePublic;	/*!< key filename with suffix "public" */

	bool fixPolyMod; /*!< Fixed polynomial modulus flag */

	bool plainLength; /*!< Write length of last block to ciphertext as plaintext */

	bool verbose; /*!< Verbose flag */

	/**
	 * Returns an irreducible polynomial.
	 * The function searches for a cyclotomic
	 * polynomial with degree equal to n.
	 * \param n Degree
	 * \return Irreducible polynomial
	 */
	ZZX getIrredPoly(int n);

	/**
	 * Returns the n-th cyclotomic polynomial.
	 * \param n Identifier for the cyclotomic polynomial
	 * \return N-th cyclotomic polynomial
	 */
	ZZX cycloPoly(int n);

	/**
	 * Euler's totient function.
	 * \param n Input for Euler's totient function
	 * \return value of Euler's totient function
	 */
	int phi(int n);

	/**
	 * Calculates the greatest common divider.
	 * \param a a
	 * \param b b
	 * \return GCD(a,b)
	 */
	int gcd(int a, int b);

	/**
	 * Transforms all characters of a string to lower-case characters.
	 * \param str String of characters
	 * \return String only with lower-case characters
	 */
	string tolowerStr(string str);

	/**
	 * Prints usage of the program.
	 */
	void usage(void);
};


/* Global operators */

/**
 * Reads mode from stream and sets parameters for encryption scheme.
 * \param stream Input stream
 * \param parameter Pointer to Parameter object
 * \return Updated stream
 */
istream& operator>>(istream& stream, Parameters& parameter);

/**
 * Writes mode and parameters to stream.
 * \param stream Output stream
 * \param parameter Pointer to Parameter object
 * \return Updated stream
 */
ostream& operator<<(ostream& stream, Parameters& parameter);

#endif /* PARAMETERS_H_ */
