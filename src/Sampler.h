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
 * Sampler.h
 *
 *  Created on: 11.08.2011
 */

#ifndef SAMPLER_H_
#define SAMPLER_H_

#include <math.h>
#include <stdlib.h>
#include <time.h>
/* NTL library for big integers */
#include <NTL/ZZ_pE.h>

NTL_CLIENT

#include "Constants.h"

/**
 * Class for sampling values. This class
 * enables producing values that succeed
 * a given probability distribution. The
 * distributions are the uniform and the
 * gaussian distribution.
 */
class Sampler {
public:
	/**
	 * Initializes the sampler. It sets all possible constant
	 * values for more efficient sampling.
	 * \param s Gaussian parameter
	 */
	Sampler(float s);

	virtual ~Sampler();

	/**
	 * Samples gaussian distributed polynomial.
	 * \param n Length of polynomial
	 * \return Polynomial with gaussian distributed coefficients
	 */
	ZZ_pE sampleGaussPoly(int n);

	/**
	 * Samples uniform distributed polynomial.
	 * \param n Length of polynomial
	 * \return Polynomial with uniform distributed coefficients
	 */
	ZZ_pE sampleUniPoly(int n);

private:
	/* Constant values */
	float constLeft, constRight, constPowS2, constX1;
	int constX2;

	/**
	 * Samples a single gaussian distributed value.
	 * This function makes use of the "rejection sampling" method.
	 * \return Gaussian distributed value
	 */
	ZZ_p sampleD(void);
};

#endif /* SAMPLER_H_ */
