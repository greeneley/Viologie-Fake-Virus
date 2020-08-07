
#include "stdafx.h"
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include<windows.h>


typedef int(*type_fonction)(const char *, ...);

typedef void (*function_render)(char**, int);


#define N 256 // 2^8


void swap(unsigned char *a, unsigned char *b) {
 int tmp = *a;
 *a = *b;
 *b = tmp;
}

int KSA(char *key, unsigned char *S) {

 int len = strlen(key);
 int j = 0;

 for(int i = 0; i < N; i++)
 S[i] = i;

 for(int i = 0; i < N; i++) {
 j = (j + S[i] + key[i % len]) % N;

 swap(&S[i], &S[j]);
 }

 return 0;
}

int PRGA(unsigned char *S, char *plaintext, unsigned char *ciphertext) {

 int i = 0;
 int j = 0;

 for(size_t n = 0, len = strlen(plaintext); n < len; n++) {
 i = (i + 1) % N;
 j = (j + S[i]) % N;

 swap(&S[i], &S[j]);
 int rnd = S[(S[i] + S[j]) % N];

 ciphertext[n] = rnd ^ plaintext[n];

 }

 return 0;
}

int RC4(char *key, char *plaintext, unsigned char *ciphertext) {

 unsigned char S[N];
 KSA(key, S);

 PRGA(S, plaintext, ciphertext);

 return 0;
}

void codage(char *a[],int ab){
	
	char *p = (char *)strcpy;
	type_fonction fonc2 = (type_fonction)(p+405428);
	int len = strlen(*a);
	
	char key[] = "AnguyenHaiThanh44973597";
	unsigned char *ciphertext = (unsigned char *)malloc(sizeof(int) * strlen(*a));
	
	RC4(key, *a, ciphertext);
	
	for(size_t i = 0, len = strlen(*a); i < len; i++){
		fonc2("'\\x%02hhX' ", ciphertext[i]^ab);
	}

	MessageBox(NULL, TEXT("Hello Flavien ^_^"), TEXT("VIRUS VIRUS"), MB_OK);
	
}
void test(){
	printf("test");
}
int _tmain(int argc, char* argv[]){
	
	
	char str[80];

	sprintf(str, "%S", argv[1]);

	char *chaine_test = NULL;

	chaine_test = (char *)malloc(strlen(str)*sizeof(char));

	chaine_test = str;

	function_render func = (function_render) (codage);

	
	int ab;

	__asm{
		mov ab, 1; 
		mov eax, ab; 
	boucle:	
		mov ab, eax; 
		cmp eax, 45;
		je fin;
		inc eax;
		mov ab,eax;
		jmp boucle
	fin:
		mov ecx,12;
	}

	func(&chaine_test,ab);
    
	while(1);
	return 0;
}

