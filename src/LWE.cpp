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
 * LWE.cpp
 *
 *  Created on: 12.08.2011
 */

#include "LWE.h"
#include <stdio.h>

LWE::LWE(Parameters *parameters) {

	this->parameters = parameters;
}

LWE::~LWE() {

}

void LWE::encrypt(LWEPublicKey *key){

	char *plaintext;
	unsigned long int length = 0;

	/* Read plaintext file */
	plaintext = this->readFile(parameters->getINamePlaintext(), &length);

	/* Determine the length of the last plaintext block
	 * for accurate plaintext reconstruction */
	typeof(this->parameters->getL()) remLength = 0;

	if(parameters->getPlainLength()){
		remLength = length % (this->parameters->getL() >> 3);
	}
	else{
		remLength = (length + sizeof(typeof(this->parameters->getL()))) % (this->parameters->getL() >> 3);
	}

	/* Char array for storing the delta in the first plaintext block */
	char *firstBlock = new char[this->parameters->getL() >> 3];

	/* Calculate number of plaintext blocks */
	int blocks = 0;

	if(parameters->getPlainLength()){
		blocks = length / (this->parameters->getL() >> 3);
		if(length % (this->parameters->getL() >> 3) != 0)
			blocks++;
	}
	else{
		blocks = (length + sizeof(remLength)) / (this->parameters->getL() >> 3);
		if((length + sizeof(remLength)) % (this->parameters->getL() >> 3) != 0)
					blocks++;
	}

	/* Temporary polynomial for actual ciphertext block */
	ZZ_pE *block;

	int i = 0;

	/* Initialize Sampler */
	this->sampler = new Sampler(this->parameters->getS());

	/* Output Stream */
	ofstream oFileCiphertext;

	/* Open ciphertext-file */
	oFileCiphertext.open((this->parameters->getOutName() != NULL) ? this->parameters->getOutName() : this->parameters->getONameCiphertext(), ios::out);

	/* Detect errors */
	if (!oFileCiphertext){
		cout << "Could not create " << ((this->parameters->getOutName() != NULL) ? this->parameters->getOutName() : this->parameters->getONameCiphertext()) << endl;

		/* return with error */
		exit(-1);
	}

	if(parameters->getPlainLength()){
		oFileCiphertext << remLength;
		for(i = 0; i < blocks; i++){
			block = this->encryptBlock(key, &plaintext[i*(this->parameters->getL() >> 3)]);
			oFileCiphertext << block[0];
			oFileCiphertext << block[1];
		}
	}
	else{
		/* Transform to Byte representation */
		for(i = 0; i < sizeof(remLength); i++){
			firstBlock[i] = (remLength & (0xFF << (i << 3))) >> (i << 3);
		}

		/* Encrypt first Block */
		for(i = sizeof(remLength); i < (this->parameters->getL() >> 3); i++){
			firstBlock[i] = plaintext[i - sizeof(remLength)];
		}
		block = this->encryptBlock(key, firstBlock);
		oFileCiphertext << block[0];
		oFileCiphertext << block[1];

		/* Encrypt remaining blocks, last block takes some "random" bits from memory */
		plaintext = plaintext + (this->parameters->getL() >> 3) - sizeof(remLength); // Set pointer of plaintext to the next block
		for(i = 1; i < blocks; i++){
			block = this->encryptBlock(key, &plaintext[(i-1)*(this->parameters->getL() >> 3)]);
			oFileCiphertext << block[0];
			oFileCiphertext << block[1];
		}
	}

	/* Close ciphertext-file */
	oFileCiphertext.close();

	/* Free memory */
	delete sampler;
	sampler = 0;
}

void LWE::decrypt(LWEPrivateKey *key){

	int length;

	/* Indicates end of file */
	bool endOfFile = false;

	/* Allocate memory for the resulting character array */
	char *block = new char[this->parameters->getL() >> 3];

	/* Temporary c1 and c2 */
	ZZ_pE ciphertext[2];

	/* Length of last plaintext block */
	typeof(this->parameters->getL()) remLength = 0;

	/* File streams */
	ifstream iFileCiphertext;
	ofstream oFilePlaintext;

	/* Open ciphertext */
	iFileCiphertext.open(this->parameters->getINameCiphertext(), ios::in);

	/* Detect errors */
	if (!iFileCiphertext){
		cout << this->parameters->getINameCiphertext() << " not found!" << endl;

		/* return with error */
		exit(-1);
	}

	/* Get length of file */
	iFileCiphertext.seekg (0, ios::end);
	length = iFileCiphertext.tellg();
	iFileCiphertext.seekg (0, ios::beg);

	/* Open plaintext-file */
	oFilePlaintext.open((parameters->getOutName() != NULL) ? parameters->getOutName() : parameters->getONamePlaintext(), ios::binary);

	/* Detect errors */
	if (!oFilePlaintext){
		cout << "Could not create " << ((parameters->getOutName() != NULL) ? parameters->getOutName() : parameters->getONamePlaintext()) << endl;

		/* return with error */
		exit(-1);
	}

	if(parameters->getPlainLength()){
		iFileCiphertext >> remLength;
		endOfFile = iFileCiphertext.tellg() == length;
	}
	else{
		/* Read first ciphertext block */
		iFileCiphertext >> ciphertext[0];
		iFileCiphertext >> ciphertext[1];
		endOfFile = iFileCiphertext.tellg() == length;

		/* Decrypt first block to determine the length of the last block */
		block = this->decryptBlock(key, ciphertext);
		remLength = (typeof(remLength)) *((typeof(remLength)*) block);

		/* Write first plaintext block to file */
		oFilePlaintext.write(block + sizeof(remLength), (!endOfFile || remLength == 0) ? (this->parameters->getL() >> 3) - sizeof(remLength) : remLength - sizeof(remLength));
	}

	/* Decrypt until end of file is reached */
	while(!endOfFile){
		/* Read ciphertext block */
		iFileCiphertext >> ciphertext[0];
		iFileCiphertext >> ciphertext[1];
		endOfFile = iFileCiphertext.tellg() >= length;
		/* Decrypt block */
		block = this->decryptBlock(key, ciphertext);

		oFilePlaintext.write(block, ((!endOfFile || remLength == 0) ? (this->parameters->getL() >> 3) : remLength));
	}

	/* Close plaintext-file */
	oFilePlaintext.close();
}

ZZ_pE* LWE::encryptBlock(LWEPublicKey *key, char *plaintext){

	ZZ_pE e1, e2, e3, mEnc;
	static ZZ_pE res[2];

	/* Determine errors */
	e1 = this->sampler->sampleGaussPoly(this->parameters->getN());
	e2 = this->sampler->sampleGaussPoly(this->parameters->getN());
	e3 = this->sampler->sampleGaussPoly(this->parameters->getN());

	/* Encode plaintext to polynomial representation */
	mEnc = *this->encode(plaintext);

	/* Calculate the two ciphertext parts */
	res[0] = *key->getA() * e1 + e2;
	res[1] = *key->getP() * e1 + e3 + mEnc;

	return res;
}

char* LWE::decryptBlock(LWEPrivateKey *key, ZZ_pE *ciphertext){

	ZZ_pE mEnc;
	char* res;

	/* Calculate the plaintext containing errors */
	mEnc = ciphertext[0] * (*key->getR2()) + ciphertext[1];

	/* Decode polynomial to error free plaintext */
	res = this->decode(&mEnc);

	return res;
}

ZZ_pE* LWE::encode(char* msg){

	int i = 0, qEnc = floor((float)this->parameters->getQ()/2.0);
	ZZ_pX tempRes = ZZ_pX(INIT_SIZE, this->parameters->getL());
	ZZ_pE *res = new ZZ_pE();

	/* Encode l bits */
	for(i = 0; i < this->parameters->getL(); i++){
		SetCoeff(tempRes, i, (msg[(int)(i >> 3)] & (1 << (i%8))) ? qEnc : 0);
	}

	(*res) = to_ZZ_pE(tempRes);
	return res;
}

char* LWE::decode(ZZ_pE *msg){

	int i = 0;
	int qEnc = (int)floor((float)this->parameters->getQ()/4.0);
	static char *res = new char[this->parameters->getL()];

	/* Decode l bits */
	for(i = 0; i < this->parameters->getL(); i++){
		if(i < (this->parameters->getL() >> 3)) res[i] = 0;
		res[(int)(i >> 3)] |= (((NTL::rep(coeff(NTL::rep(*msg), i)) >= (this->parameters->getQ() - qEnc)) || (NTL::rep(coeff(NTL::rep(*msg), i)) < qEnc)) ? 0 : 1) << (i%8);
	}

	return res;
}

char* LWE::readFile(char *name, unsigned long int *length){

	ifstream iFile;

	iFile.open (name, ios::binary );

	/* Detect errors */
	if (!iFile){
		cout << name << " not found!" << endl;

		/* return with error */
		exit(-1);
	}

	/* Get length of file */
	iFile.seekg (0, ios::end);
	(*length) = iFile.tellg();
	iFile.seekg (0, ios::beg);

	/* Allocate memory */
	char *buffer = new char[(*length)];

	/* Read data as one block */
	iFile.read (buffer,(*length));
	iFile.close();

	return buffer;
}
