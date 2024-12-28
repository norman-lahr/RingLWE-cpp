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
 * main.cpp
 *
 *  Created on: 11.08.2011
 */

#include "main.h"

int main(int argc, char *argv[]){

	/* Input Streams */
	ifstream iFileKey;

	/* Output Streams */
	ofstream oFilePublicKey,
			 oFilePrivateKey;

	/* Crypto engine and key */
	LWE *LWEengine;
	LWEKeypair *key;
	LWEPublicKey *publicKey;
	LWEPrivateKey *privateKey;

	/* Read options from command line and set all parameters */
	Parameters *parameters = new Parameters(argc, argv);

	/* Switch between encryption, decryption and key generation */
	switch (parameters->getOpMode()) {
		case ENC:

			/* Get Public Key */
			iFileKey.open(parameters->getNameKey(), ios::in);

			/* Detect errors */
			if (!iFileKey){
				cout << parameters->getNameKey() << " not found!" << endl;

				/* Return with error */
				exit(-1);
			}

			/* Read mode and set parameters */
			iFileKey >> *parameters;

			/* Create new public key object */
			publicKey = new LWEPublicKey();

			/* Read public key */
			iFileKey >> publicKey;

			iFileKey.close();

			/* Create token */
			LWEengine = new LWE(parameters);

			/* Encrypt plaintext and write ciphertext to file */
			LWEengine->encrypt(publicKey);

			/* Free memory */
			delete publicKey;
			publicKey = NULL;
			delete LWEengine;
			LWEengine = NULL;

			break;

		case DEC:
			/* Get Public Key */
			iFileKey.open(parameters->getNameKey(), ios::in);

			/* Detect errors */
			if (!iFileKey){
				cout << parameters->getNameKey() << " not found!" << endl;

				/* Return with error */
				exit(-1);
			}

			/* Read mode and set parameters */
			iFileKey >> *parameters;

			/* Create new private key object */
			privateKey = new LWEPrivateKey();

			/* Read private key from file */
			iFileKey >> privateKey;

			iFileKey.close();

			/* Create token */
			LWEengine = new LWE(parameters);

			/* Decrypt Ciphertext and wirte Plaintext to file */
			LWEengine->decrypt(privateKey);

			/* Free memory */
			delete privateKey;
			privateKey = NULL;
			delete LWEengine;
			LWEengine = NULL;

			break;

		case GEN:

			/* Generate new keypair */
			key = new LWEKeypair(parameters);

			/* Write Keys to file */
			oFilePrivateKey.open(parameters->getNamePrivate().c_str(), ios::out);
			oFilePublicKey.open(parameters->getNamePublic().c_str(), ios::out);

			if (!oFilePrivateKey || !oFilePublicKey){
				cout << "Could not open key files!" << endl;
				/* Return with error */
				exit(-1);
			}

			/* Write private key file */
			oFilePrivateKey << *parameters;
			oFilePrivateKey << *key->getPrivateKey();
			oFilePrivateKey.close();

			/* Write public key file */
			oFilePublicKey << *parameters;
			oFilePublicKey << *key->getPublicKey();
			oFilePublicKey.close();

			break;

		default:
			break;
	}

	/* Free memory */
	delete parameters;
	parameters = NULL;

	return 0;//exit(0);
}
