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
 * Parameters.cpp
 *
 *  Created on: 11.08.2011
 */

#include "Parameters.h"

Parameters::Parameters(int argc, char *argv[]) {

	string temp;
	int found;

	/* Init */
	this->outName = NULL;

	/* Read options */
	int optC;

	/* Initialize fixed seed flag */
	bool fixedSeed = false;

	/* Initialize  plainLength flag*/
	this->plainLength = false;

	/* Initialize mode and parameters */
	this->mode = MAN;
	this->n = INITN;
	this->q = INITQ;
	this->s = INITS;
	this->c = INITC;
	this->d = INITD;
	this->l = INITL;

	/* Initialize verbose flag */
	this->verbose = false;

	/* Initialize fixed polynomial modulus flag */
	this->fixPolyMod = false;

			/* Show help if there are no arguments */
	if(argc == 1){
	   this->usage();
	   exit(-1);
	}

	while (1) {
	   static struct option long_options[] =
		 {
		   {"enc"	,  required_argument, 0, 'e'},
		   {"dec"	,  required_argument, 0, 'd'},
		   {"key"	,  required_argument, 0, 'k'},
		   {"genkey",  required_argument, 0, 'g'},
		   {"out"	,  required_argument, 0, 'o'},
		   {"fixseed"	,  required_argument, 0, 'f'},
		   {"fixpolymod"	,  no_argument, 0, 'm'},
		   {"delta"	,  required_argument, 0, 'r'},
		   {"plainlength"	,  no_argument, 0, 'p'},
		   {"verbose"	,  no_argument, 0, 'v'},
		   {"help"	,  no_argument, 0, 'h'},
		   {0, 0, 0, 0}
		 };
	   /* getopt_long stores the option index here. */
	   int option_index = 0;

	   optC = getopt_long (argc, argv, "e:d:k:g:o:fr:c:n:l:q:s:vhmp",
						long_options, &option_index);

	   /* Detect the end of the options. */
	   if (optC == -1)
		 break;

	   switch (optC)
		 {
		 case 'e': // enc
			 this->opMode = ENC;
			 this->iNamePlaintext = optarg;

			 temp = string(this->iNamePlaintext).append(".enc");
			 this->oNameCiphertext = new char[temp.length()+1]; // + '\0'
			 strncpy(this->oNameCiphertext,temp.c_str(), temp.length()+1);

			 break;

		 case 'd': // dec
			 this->opMode = DEC;
			 this->iNameCiphertext = optarg;

			 temp = string(this->iNameCiphertext);
			 found =  temp.rfind(".enc");

			 if(found != temp.npos){
				 temp.erase(temp.begin() + found, temp.end());
				 this->oNamePlaintext = new char[temp.length()+1]; // + '\0'
				 strncpy(this->oNamePlaintext, temp.c_str(), temp.length()+1);
			 }

			 break;

		 case 'k': // key
			 this->iNameKey = optarg;
		   break;

		 case 'g': // genkey
			 this->opMode = GEN;

			 if((tolowerStr(string(optarg)).compare("easy")) == 0)			this->mode = EASY;
			 else if((tolowerStr(string(optarg)).compare("low")) == 0)		this->mode = LOW;
			 else if((tolowerStr(string(optarg)).compare("medium")) == 0)	this->mode = MEDIUM;
			 else if((tolowerStr(string(optarg)).compare("high")) == 0)		this->mode = HIGH;
			 else if((tolowerStr(string(optarg)).compare("man")) == 0)		this->mode = MAN;
			 else cout << "Mode " << optarg << " is not supported!" << endl;

			break;

		 case 'o': // out
			 this->outName = optarg;
			 if(this->opMode == GEN){
				this->namePrivate = string(this->outName) + ".private";
				this->namePublic = string(this->outName) + ".public";
			 }

			 break;

		 case 'f': // fix value for PRNG
			 fixedSeed = true;

			 break;

		 case 'm': // fix polynomial modulus
		 			 fixPolyMod = true;

		 			 break;

		 case 'r': // set delta
			 this->d = atof(optarg);

			 break;

		 case 'c':	// set c
			 c = atof(optarg);

			 break;

		 case 'n': // set n
			 this->n = atoi(optarg);

			 break;

		 case 'q': // set q
			 this->q = atoi(optarg);

			 break;

		 case 's': // set s
			 this->s = atof(optarg);

			 break;

		 case 'l': // set l
			 this->l = atoi(optarg);

			 break;

		 case 'p':  // set verbose flag
		 			 this->plainLength = true;

		 			 break;

		 case 'v':  // set verbose flag
			 this->verbose = true;

			 break;

		 case 'h': //help
			 this->usage();
			 break;

		 default:
			 usage();
		 }
	 }

	/* Set parameters, if a key will be generated.
	 * In case of enc-/decryption all relevant parameters
	 * can be read out of the key file.
	 */
	if (this->opMode == GEN) this->setParameters();

	if(fixedSeed){
		/* initialize pseudo-random-generator with fixed seed */
		srand (NULL);

		/* Set the seed of NTL's pseudo-number generator to fixed value */
		SetSeed(to_ZZ(NULL));
	}
	else{
		/* initialize pseudo-random-generator */
		srand (time(NULL));

		/* Set the seed of NTL's pseudo-number generator */
		SetSeed(to_ZZ(time(NULL)));
	}
}

Parameters::~Parameters() {

	delete this->oNamePlaintext;
	delete this->oNameCiphertext;

	this->oNamePlaintext = NULL;
	this->oNameCiphertext = NULL;
}

int Parameters::getL() {
	return this->l;
}

int Parameters::getMode() {
	return this->mode;
}

int Parameters::getN() {
	return this->n;
}

char* Parameters::getINameCiphertext() {
	return this->iNameCiphertext;
}

char* Parameters::getONameCiphertext() {
	return this->oNameCiphertext;
}

char* Parameters::getNameKey() {
	return this->iNameKey;
}

char* Parameters::getINamePlaintext() {
	return this->iNamePlaintext;
}

char* Parameters::getONamePlaintext() {
	return this->oNamePlaintext;
}

int Parameters::getOpMode() {
	return this->opMode;
}

char* Parameters::getOutName() {
	return this->outName;
}

int Parameters::getQ() {
	return this->q;
}

float Parameters::getS() {
	return this->s;
}

float Parameters::getD(){
	return this->d;
}

float Parameters::getC(){
	return this->c;
}
string Parameters::getNamePrivate(){
	return this->namePrivate;
}

string Parameters::getNamePublic(){
	return this->namePublic;
}

void Parameters::setMode(int mode) {
	this->mode = mode;
	this->setParameters();
}

void Parameters::setParameters() {

	/* Constant c, determined so that the probability of
	 * choosing a 'bad' encryption vector e is at most
	 * 2^-40 */
	float tmpC = 0.0;

	stringstream strs;

	/* Set Mode, optional delta, optional c */
	if(mode != MAN){

		switch (this->mode) {
		case EASY:
		case EASYD:
		case EASYDC:
			this->n = 128;
			this->q = 2053;
			tmpC = (c == INITC) ? 1.35 : c;
			this->s = sqrt((sqrt(2.0) * PI * ((float)this->q/4.0))/(tmpC * sqrt(2 * this->n * log(2.0/this->d))));//6.77;
			break;
		case LOW:
		case LOWD:
		case LOWDC:
			this->n = 192;
			this->q = 4093;
			tmpC = (c == INITC) ? 1.28 : c;
			this->s = sqrt((sqrt(2.0) * PI * ((float)this->q/4.0))/(tmpC * sqrt(2 * this->n * log(2.0/this->d))));//8.87;
			break;
		case MEDIUM:
		case MEDIUMD:
		case MEDIUMDC:
			this->n = 256;
			this->q = 4093;
			tmpC = (c == INITC) ? 1.25 : c;
			this->s = sqrt((sqrt(2.0) * PI * ((float)this->q/4.0))/(tmpC * sqrt(2 * this->n * log(2.0/this->d))));//8.35;
			break;
		case HIGH:
		case HIGHD:
		case HIGHDC:
			this->n = 320;
			this->q = 4093;
			tmpC = (c == INITC) ? 1.22 : c;
			this->s = sqrt((sqrt(2.0) * PI * ((float)this->q/4.0))/(tmpC * sqrt(2 * this->n * log(2.0/this->d))));//8.0;
			break;
		default:
			break;
		}

		/* If d is chosen manually, the mode will be
		 * incremented by 4. If also c is set manually,
		 * then the mode will be incremented by 8. */
		if(this->d != INITD && this->opMode == GEN){
			if(this->c != INITC)
				this->mode += 8;
			else
				this->mode += 4;
		}
	}

	/* Set n, l, q, s manually */
	else{
		/* s is determined by manually chosen n, q and c */
		if(this->s == INITS && this->n != INITN && this->q != INITQ && this->c != INITC){
			this->s = sqrt((sqrt(2.0) * PI * ((float)this->q/4.0))/(this->c * sqrt(2 * this->n * log(2.0/this->d))));
		}

		if(this->n == INITN || this->q == INITQ || this->s == INITS){
			cout << "You wanted to choose n, l, q and s manually, but one or more are missing!" << endl;
			exit(-1);
		}

		if(this->l > this->n){
			cout << "You wanted to choose n, l, q and s manually, but l has to be smaller or equal than n!" << endl;
			exit(-1);
		}

		if(this->q < 2){
			cout << "You wanted to choose n, l, q and s manually, but q has to be greater than 2!" << endl;
			exit(-1);
		}

		if(this->n < 1){
			cout << "You wanted to choose n, l, q and s manually, but n has to be greater than 1!" << endl;
			exit(-1);
		}


		if(this->l < 1){
			cout << "You wanted to choose n, l, q and s manually, but l has to be greater than 1!" << endl;
			exit(-1);
		}
	}

	if(this->verbose){
		cout << endl << "Parameters: " << endl << "========================" << endl;
		cout << "Mode:\t";
		switch (mode) {
			case EASY:
				cout << "EASY";
				break;
			case LOW:
				cout << "LOW";
				break;
			case MEDIUM:
				cout << "MEDIUM";
				break;
			case HIGH:
				cout << "HIGH";
				break;
			case EASYD:
				cout << "EASY with manual delta";
				break;
			case LOWD:
				cout << "LOW with manual delta";
				break;
			case MEDIUMD:
				cout << "MEDIUM with manual delta";
				break;
			case HIGHD:
				cout << "HIGH with manual delta";
				break;
			case EASYDC:
				cout << "EASY with manual delta and c";
				break;
			case LOWDC:
				cout << "LOW with manual delta and c";
				break;
			case MEDIUMDC:
				cout << "MEDIUM with manual delta and c";
				break;
			case HIGHDC:
				cout << "HIGH with manual delta and c";
				break;
			case MAN:
				cout << "MANUALLY";
				break;
			default:
				break;
		}
		cout << endl;
		cout << "Delta:\t" << this->d << endl;
		cout << "c:\t" << ((tmpC != 0.0 ) ? tmpC : this->c) << endl;
		cout << "s:\t" << this->s << endl;
		cout << "n:\t" << this->n << endl;
		cout << "q:\t" << this->q << endl;
		cout << "l:\t" << this->l << endl;
		cout << endl;
	}

	/* Set modulus */
	ZZ_p::init(to_ZZ(this->q));
	/* Set polynomial modulus to an cyclotomic (and irreducible) polynomial */
	ZZ_pE::init(to_ZZ_pX(getIrredPoly(this->n)));

	if(this->verbose) cout << "f(x): " << ZZ_pE::modulus() << endl;
}

void Parameters::setNameCiphertext(char *iNameCiphertext) {
	this->iNameCiphertext = iNameCiphertext;
}

void Parameters::setNameKey(char *iNameKey) {
	this->iNameKey = iNameKey;
}

void Parameters::setNamePlaintext(char *iNamePlaintext) {
	this->iNamePlaintext = iNamePlaintext;
}

void Parameters::setOpMode(int opMode) {
	this->opMode = opMode;
}

void Parameters::setOutName(char *outName) {
	this->outName = outName;
}

void Parameters::setN(int n){
	this->n = n;
}

void Parameters::setQ(int q){
	this->q = q;
}

void Parameters::setL(int l){
	this->l = l;
}

void Parameters::setS(float s){
	this->s = s;
}

void Parameters::setD(float d){
	this->d = d;
}

void Parameters::setC(float c){
	this->c = c;
}

bool Parameters::getPlainLength(){
	return this->plainLength;
}

ZZX Parameters::getIrredPoly(int n){

	if(log2(n) - (int)log2(n) == 0.0 || this->fixPolyMod){
		ZZX f = ZZX();
		SetCoeff(f, 0, 1);
		SetCoeff(f, n, 1);
		return f;
	}

	int m = n;
	int phi_m = phi(m);
	bool existence = true;

	while(phi_m != n && existence){
		existence = m < 10*n; // estimated lower bound of euler's totient function
		m++;
		phi_m = phi(m);
	}

	if(!existence){
		cout << "There is no cyclotomic polynmial with degree " << n << "!" << endl << "Please choose another value for n." << endl;
		exit(-1);
	}

	return cycloPoly(m);
}

ZZX Parameters::cycloPoly(int n){


	ZZX num = ZZX();
	ZZX denom = ZZX(0,1);

	if(n == 1){
		SetCoeff(num, 1, 1);
		SetCoeff(num, 0, -1);
		return num;
	}

	SetCoeff(num, n, 1);
	SetCoeff(num, 0, -1);

	for(int i = 1; i < n; i++){
		if(n % i == 0){
			denom *= cycloPoly(i);
		}
	}

	return num/denom;
}

int Parameters::phi(int n){

	int num = 0;

	for(int i = 1; i < n; i++){
		if(gcd(n,i) == 1) num++;
	}

	return num;
}

int Parameters::gcd(int a, int b){

	int r;

	a = abs(a);
	b = abs(b);

	while(b != 0){
		r = a % b;
		a = b;
		b = r;
	}

	return a;
}
string Parameters::tolowerStr(string str){

	 locale loc;
	 string res;

	  for (size_t i=0; i<str.length(); ++i)
	    res += tolower(str[i],loc);

	  return res;
}

void Parameters::usage(){
	cout << "Usage: LWE-Polynomial [OPTION] ..." << endl << endl;
	cout << "-e,  --enc [Filename]\tEncrypts a file with name \"Filename\".\n\t\t\tThe encrypted file takes postfix \"*.enc\" \n\t\t\tby default or you can choose your own \n\t\t\tfilename with option \"-o,  --out\"" << endl<< endl;
	cout << "-d,  --dec [Filename]\tDecrypts a file with name \"Filename\".\n\t\t\tThe filename of the decrypted file is either \n\t\t\tthe current filename without optional \n\t\t\tpostfix \"*.enc\" or you can choose \n\t\t\tyour own filename with option \"-o,  --out\"" << endl<< endl;
	cout << "-g,  --genkey [Mode]\tGenerates a new pair of keys with \n\t\t\tgiven cipher mode. The predefined\n\t\t\tmodes are defined in the publication\n\t\t\t\"Better key sizes (and attacks) for\n\t\t\tLWE-based encryption\" of Lindner and Peikert."
			"\n\n\t\t\tMode\tn\tq\ts"
			"\n\t\t\t============================"
			"\n\t\t\tEASY\t128\t2053\t6.77"
			"\n\t\t\tLOW\t192\t4093\t8.87"
			"\n\t\t\tMEDIUM\t256\t4093\t8.35"
			"\n\t\t\tHIGH\t320\t4093\t8.00"
			"\n\t\t\t----------------------------"
			"\n\t\t\tMAN\t-n\t-q\t-s"
			"\n\n\t\t\tFor all modes above you can choose an \n\t\t\talternative value for delta and optional for c if delta \n\t\t\tis set by options \"-r\" and \"-c\". \n\t\t\tWith these options a new s will be determined. \n\n\t\t\tIn addition, you can select parameters n, q and s \n\t\t\tmanually by using options \"-n\", \"-q\", \"-s\"." << endl << "\t\t\tIf you manually select \"-n\", \"-q\", \"-c\"\n\t\t\tand optionally \"-r\", parameter s is determined \n\t\t\tby these values."<< endl<< endl; //Manually
	cout << "-o,  --out [Filename]\tSpecifies the output filename." << endl << endl;
	cout << "-k,  --key [Filename]\tSpecifies the key filename." << endl << endl;
	cout << "-f, --fixseed\t\tSets seed of pseudo-random-number-generators \n\t\t\tto a fixed value." << endl << endl;
	cout << "-m, --fixpolymod\tSets polynomial modulus to f(x)=x^n+1 for all n." << endl << endl;
	cout << "-r, --delta [value]\tSets per-symbol error probability.\n\t\t\tDefault: delta = 0.01" << endl << endl;
	cout << "-c [value]\t\tSets parameter c." << endl << endl;
	cout << "-n [value]\t\tSets parameter n." << endl << endl;
	cout << "-l [value]\t\tSets message length l.\n\t\t\tDefault: l = 128" << endl << endl;
	cout << "-q [value]\t\tSets modulus q." << endl << endl;
	cout << "-s [value]\t\tSets parameter s." << endl << endl;
	cout << "-p, --plainlength \tInstructs the encrypt function to \n\t\t\twrite the length of the remaining bytes \n\t\t\tof the last block as plaintext into the \n\t\t\tciphertext-file." << endl << endl;
	cout << "-v,  --verbose\t\tPrints actual parameters." << endl << endl;
	cout << "-h,  --help\t\tPrints this help." << endl << endl;
}

istream& operator>>(istream& stream, Parameters& parameter) {

	/* Read mode from stream */
	int mode;
	int n, q, l;
	float s, d, c;

	stream >> mode;

	if(mode == MAN){
		stream >> n;
		stream >> q;
		stream >> s;
		stream >> l;
		parameter.setN(n);
		parameter.setQ(q);
		parameter.setS(s);
		parameter.setL(l);
	}
	else if(mode >= EASYD && mode <= HIGHD){
		stream >> d;
		parameter.setD(d);
	}
	else if(mode >= EASYDC && mode <= HIGHDC){
		stream >> d;
		stream >> c;
		parameter.setD(d);
		parameter.setC(c);
	}

	parameter.setMode(mode);

	return stream;
}

ostream& operator<<(ostream& stream, Parameters& parameter) {

	stream << parameter.getMode() << " ";

	if(parameter.getMode() == MAN){
		stream << parameter.getN() << " ";
		stream << parameter.getQ() << " ";
		stream << parameter.getS() << " ";
		stream << parameter.getL() << " ";
	}
	else if(parameter.getMode() >= EASYD && parameter.getMode() <= HIGHD){
		stream << parameter.getD() << " ";
	}
	else if(parameter.getMode() >= EASYDC && parameter.getMode() <= HIGHDC){
		stream << parameter.getD() << " ";
		stream << parameter.getC() << " ";
	}

	return stream;
}
