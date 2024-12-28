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
 * Constants.h
 *
 *  Created on: 11.08.2011
 */

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

/* Operation modes */
#define ENC 0
#define DEC 1
#define GEN 2

/* Cipher modes */
#define MAN 0
#define EASY 1
#define LOW 2
#define MEDIUM 3
#define HIGH 4

#define EASYD 5
#define LOWD 6
#define MEDIUMD 7
#define HIGHD 8

#define EASYDC 9
#define LOWDC 10
#define MEDIUMDC 11
#define HIGHDC 12

#define INITD (float)0.01 // Set error-rate to 10^-4
#define INITN -1
#define INITC (float)0.0
#define INITQ -1
#define INITS (float)0.0
#define INITL 128

/* Indices of known irreducible polynomials */
#define IRREDPOLY_192_4093 0
#define IRREDPOLY_320_4093 1

/* Pi */
#define PI 3.14159265

#endif /* CONSTANTS_H_ */
