/* Author: Michael Ton
 * Assignment: Program 4 - OTP
 * Description: otp_enc_d.c file sets up daemon server, receiving data for encryption before sending it back to socket. File structure based off of files provided by assignment instructions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>

// Error function used for reporting issues
void error(const char *msg) { 
	perror(msg);
	exit(1); 
}

// Function receives text to be encrytped along with cipher key and encrypts the text
// Handles 'A'-'Z' and space characters; space is considered to be the ASCII value immediately after 'Z'
void encrypt(char* cipher, char* key, int len) {
	int i;

	// Iterate until all characters in cipher have been encrypted	
	for(i = 0; i < len-1; i++) {
		char c = cipher[i];
		char k = key[i];

		// Get offset value for current character in cipher
		if(c == 32)
			c = 26;
		else
			c -= 'A';

		// Get offset value for current character in key
		if(k == 32)
			k = 26;
		else
			k -= 'A';

		// Add offset values together and modulo before adding 'A' to get encrypted character
		c += k;
		c = (c % 27) + 'A';
		
		// If outside of range, subtract total number of chars in range being handled
		if(c > 91)
			c -= 27;
		// 91 is the value after Z, and will be used as the value for the space character
		// If c is 91, change it to the actual ASCII value for space and write it to the ciphertext
		if(c == 91)
			c = 32;

		cipher[i] = (char)c;
	}
}

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	char buffer[256];
	struct sockaddr_in serverAddress, clientAddress;

	// Check usage and args
	if (argc < 2) { 
		fprintf(stderr,"USAGE: %s port\n", argv[0]); 
		exit(1); 
	}

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct

	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) {
		error("ERROR opening socket");
	}

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){// Connect socket to port
		error("ERROR on binding");
	}

	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	while(1) {
		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept

		if (establishedConnectionFD < 0) {
			error("ERROR on accept");
		}

		// Create child process, handle error if unsuccessful
		pid_t cpid = fork();

		if(cpid == -1) {
			error("Unable to fork");
		}
		// If successful, verify that the connection is with correct client
		else if(cpid == 0) {
			memset(buffer, '\0', 256);

			charsRead = recv(establishedConnectionFD, buffer, 255, 0); // Read the client's message from the socket

			if (charsRead < 0) {
				error("ERROR reading from socket");	
			}

			// Correct connection will receive a value for length of plaintext content
			if(isdigit(buffer[0]) != 0) {
				// Get the length from the buffer, which is also used to initialize the byte size
				int len = atoi(&buffer[0]);
				int bytesLeft = len;

				// Send a Success message back to the client
				charsRead = send(establishedConnectionFD, "I am the server, and I got your message", 39, 0); // Send success back

				if (charsRead < 0){
					error("ERROR writing to socket");
				}

				// Initialize cipher and key variables
				char cipher[len];
				char key[len];
		
				memset(cipher, '\0', sizeof(cipher));
				memset(key, '\0', sizeof(key));	

				// Get plaintext content, ensuring all data is received before continuing
				while(bytesLeft > 0) {
					// Receive contents from socket into cipher and decrease remaining bytes accordingly
					int bytesRead = recv(establishedConnectionFD, cipher, sizeof(cipher), 0);
					bytesLeft -= bytesRead;

					if(bytesRead < 0) {
						error("Error reading file");
					}
				}

				// Send a Success message back to the client
				charsRead = send(establishedConnectionFD, "I am the server, and I got your message", 39, 0); 

				if (charsRead < 0){
					error("ERROR writing to socket");
				}

				bytesLeft = len;

				// Get key content, ensuring all data is received before continuing
				while(bytesLeft > 0) {
					// Receive contents from socket into key and decrease remaining bytes accordingly
					int bytesRead = recv(establishedConnectionFD, key, sizeof(key), 0);
					bytesLeft -= bytesRead;

					if(bytesRead < 0) {
						error("Error reading file");
					}
				}

				// Call function to encrypt plaintext
				encrypt(cipher, key, len);

				bytesLeft = len;

				// Send encrypted data, now contained in cipher, to socket, ensuring all data is sent before continuing
				while(bytesLeft > 0) {
					int bytesWritten = send(establishedConnectionFD, cipher, len, 0);
					bytesLeft -= bytesWritten;

					if(bytesWritten < 0) {
						error("Error writing to socket");
					}
				}
			}
			// If connection is not valid, send error to connecting client
			else {
				charsRead = send(establishedConnectionFD, "error", 5, 0);
			
				if(charsRead < 0){
					error("ERROR: writing to socket");
				}
	
				return(1);
			}
		}
		// Close socket
		close(establishedConnectionFD);
	}


	close(listenSocketFD); // Close the listening socket

	return 0; 
}
