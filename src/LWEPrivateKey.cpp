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
 * LWEPrivateKey.cpp
 *
 *  Created on: 12.08.2011
 */

#include "LWEPrivateKey.h"

LWEPrivateKey::LWEPrivateKey(){

}

LWEPrivateKey::LWEPrivateKey(ZZ_pE r2) {

	this->r2 = r2;
}

LWEPrivateKey::~LWEPrivateKey() {

}

ZZ_pE* LWEPrivateKey::getR2(){
	return &this->r2;
}

void LWEPrivateKey::setR2(ZZ_pE r2){
	this->r2 = r2;
}

istream& operator>>(istream& stream, LWEPrivateKey* key){

	ZZ_pE R2 = ZZ_pE();

	stream >> R2;

	key->setR2(R2);

	return stream;
}

ostream& operator<<(ostream& stream, LWEPrivateKey& key){

	stream << *key.getR2();

	return stream;
}
