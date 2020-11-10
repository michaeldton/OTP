/* Author: Michael Ton
 * E-mail: tonm@oregonstate.edu
 * Date: 3/10/20
 * Assignment: Program 4 - OTP
 * Description: keygen.c is a key generator that creates a string of random chars for use as a key for OTP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

int main(int argc, char* argv[]) {
	// Error handling for command line arguments; Send message for proper usage to stderr if invalid input received
	if(argc < 2 && !isdigit(argv[1])) {
		fprintf(stderr, "Usage: keygen keyLength\n");
		exit(1);
	}

	// Use CPU clock as random seed
	srand(time(0));

	// Symbols is string containing possible symbols for key generation
	char* symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	char* key;
	int i, len = 0;

	// Scan argument for length into int variable
	sscanf(argv[1], "%d", &len);

	// Allocate memory for string of size len + 2 for newline and null terminator chars at the end
	key = malloc((len + 2) * sizeof(char*));

	// Iterate until len number of random characters have been generated in string	
	for(i = 0; i < len; i++) {
		int pos = rand() % 27;
		key[i] = symbols[pos];
	}

	// Last two characters are \n and \0
	key[i] = '\n';
	key[i + 1] = '\0';

	// If no redirection to file received, print key to terminal
	if(argc == 2)
		printf("%s", key);

	// Free allocated memory
	free(key);

	return 0;
}

