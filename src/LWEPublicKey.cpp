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
 * LWEPublicKey.cpp
 *
 *  Created on: 12.08.2011
 */

#include "LWEPublicKey.h"

LWEPublicKey::LWEPublicKey(){

}

LWEPublicKey::LWEPublicKey(ZZ_pE a, ZZ_pE p) {

	this->a = a;
	this->p = p;
}

LWEPublicKey::~LWEPublicKey() {

}

ZZ_pE* LWEPublicKey::getA(){
	return &this->a;
}

ZZ_pE* LWEPublicKey::getP(){
	return &this->p;
}

void LWEPublicKey::setA(ZZ_pE a){
	this->a = a;
}

void LWEPublicKey::setP(ZZ_pE p){
	this->p = p;
}

istream& operator>>(istream& stream, LWEPublicKey* key){

	ZZ_pE A = ZZ_pE(),
		  P = ZZ_pE();

	stream >> A;
	stream >> P;

	key->setA(A);
	key->setP(P);

	return stream;
}

ostream& operator<<(ostream& stream, LWEPublicKey& key){

	stream << *key.getA();
	stream << *key.getP();

	return stream;
}
