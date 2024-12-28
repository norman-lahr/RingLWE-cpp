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
 * Sampler.cpp
 *
 *  Created on: 11.08.2011
 */

#include "Sampler.h"

Sampler::Sampler(float s) {
	int k;
	int num = 2 * ceil(2*s) + 1;

	/* Set all constant values for efficient sampling */
	k = ceil((float)num/s);
	this->constLeft = (float)k;
	this->constRight = (float)num/s;
	this->constPowS2 = (float)pow(s,2.0);
	this->constX1 = (num);
	this->constX2 = (num/2 + 1.0);
}

Sampler::~Sampler() {

}

ZZ_p Sampler::sampleD(){

	int x = 0;
	float u = 0;

	do {
		/* Choosing a number */
		x = ceil(((float)rand()/(float)RAND_MAX) * this->constX1) - this->constX2;	// x=[-2s,2s]
		/* Choosing the possibility */
		u = (float)rand()/(float)RAND_MAX;
	} while ((float)u * this->constLeft > this->constRight * exp((-PI*x*x)/this->constPowS2));

	return to_ZZ_p(x);

}

ZZ_pE Sampler::sampleGaussPoly(int n){

	ZZ_pX res;
	int i = 0;

	/* Pre-allocate space */
	res = ZZ_pX(INIT_SIZE, n);
	for (i = 0; i < n; i++) {
		SetCoeff(res, i, this->sampleD());
	}

	return to_ZZ_pE(res);
}

ZZ_pE Sampler::sampleUniPoly(int n){

	ZZ_pX res;
	int i = 0;

	/* Pre-allocate space */
	res = ZZ_pX(INIT_SIZE, n);
	for (i = 0; i < n; i++) {
		SetCoeff(res, i, random_ZZ_p());
	}

	return to_ZZ_pE(res);
}
