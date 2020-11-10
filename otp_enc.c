/* Author: Michael Ton
 * Assignment: Program 4 - OTP
 * Description: otp_enc.c file sets up socket with host server, sending and receiving data for OTP encryption. File structure based off of files provided by assignment instructions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <fcntl.h>

// Error function used for reporting issues
void error(const char *msg) { 
	perror(msg); 
	exit(0); 
} 

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	size_t bytesLeft, len, keyLen;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
   
	// Check usage and args 
	if (argc < 4) { 
		fprintf(stderr,"USAGE: %s myplaintext mykey port\n", argv[0]);
		exit(0); 
	}
	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct

	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address

	if (serverHostInfo == NULL) { 
		fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
		exit(0); 
	}

	// Copy in the address
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); 

	if (socketFD < 0) {
		error("CLIENT: ERROR opening socket");
	}	

	// Connect to server, connect socket to address
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
		error("CLIENT: ERROR connecting");
	}

	// Open file and obtain length
	FILE* fp = fopen(argv[1], "r");

	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, 0);

	fclose(fp);

	// Open file and obtain length
	fp = fopen(argv[2], "r");
	
	fseek(fp, 0, SEEK_END);
	keyLen = ftell(fp);
	fseek(fp, 0, 0);

	fclose(fp);

	// If total length of key is less than length of plaintext, return error
	// The key must be equal to or longer than plaintext in order to be valid
	if(keyLen < len)
		error("ERROR: unmatched lengths");

	// Set up buffer and send length to server
	char buffer[len];
	memset(buffer, '\0', sizeof(buffer));
	sprintf(buffer, "%d", len);

	charsWritten = send(socketFD, buffer, sizeof(buffer), 0); // Write to the server

	if (charsWritten < 0) {
		error("CLIENT: ERROR writing to socket");
	}

	if (charsWritten < strlen(buffer)) {
		error("CLIENT: WARNING: Not all data written to socket!");
	}

	// Get return message from server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, 39, 0); // Read data from the socket, leaving \0 at end

	if (charsRead < 0) {
		error("CLIENT: ERROR reading from socket");
	}	

	if(strncmp(buffer, "error", 5) == 0) {
		error("CLIENT: ERROR otp_enc cannot connect to otp_dec_d");
	}

	// Initialize variable containing contents of plaintext to be ciphered
	char cipher[len];
	bytesLeft = len;

	// Set file descriptor by opening plaintext file
	int fd = open(argv[1], O_RDONLY);

	// Iterate until all bytes have been sent, ensuring all data processed before moving on
	// Adapted from own code used in assignments from CS372 assignment on TCP file transfer, originally referenced from Linux/C documentation on man7.org
	while(bytesLeft > 0) {
		// Must memset cipher each iteration
		memset(cipher, '\0', sizeof(cipher));

		// Add contents to string and decrease remaining bytes accordingly
		int bytesRead = read(fd, cipher, sizeof(cipher));
		bytesLeft -= bytesRead;

		// Error handling if read failed or read is done incorrectly
		if(bytesRead < 0) {
			error("Error reading file");
		}

		// p will contain data to be sent
		void *p = cipher;

		// Iterate until all current content in cipher has been sent
		while(bytesRead > 0) {
			// Get number of bytes sent to socket
			int bytesWritten = send(socketFD, p, sizeof(cipher), 0);
		
			// Error handling if transmission failed or sent incorrectly	
			if(bytesWritten < 0) {
				error("Error writing to socket");
			}

			// Calculate bytes remaining and get position to continue from
			bytesRead -= bytesWritten;
			p += bytesWritten;
		}
	}

	close(fd);

	// Get return message from server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, 39, 0); // Read data from the socket, leaving \0 at end

	// Initialize variable containing contents of key
	char key[len];
	bytesLeft = len;

	// Set file descriptor by opening key file
	fd = open(argv[2], O_RDONLY);

	// Iterate until all bytes have been sent, ensuring all data processed before moving on
	// Adapted from own code used in assignments from CS372 assignment on TCP file transfer, originally referenced from Linux/C documentation on man7.org
	while(bytesLeft > 0) {
		// Must memset key each iteration
		memset(key, '\0', sizeof(key));

		// Add contents to string and decrease remaining bytes accordingly
		int bytesRead = read(fd, key, sizeof(key));
		bytesLeft -= bytesRead;

		// Error handling if read failed or read is done incorrectly
		if(bytesRead < 0) {
			error("Error reading file");
		}

		// p will contain data to be sent
		void *p = key;

		// Iterate until all current content in key has been sent
		while(bytesRead > 0) {
			// Get number of bytes sent to socket
			int bytesWritten = send(socketFD, p, sizeof(key), 0);

			// Error handling if transmission failed or sent incorrectly	
			if(bytesWritten < 0) {
				error("Error writing to socket");
			}

			// Calculate bytes remaining and get position to continue from
			bytesRead -= bytesWritten;
			p += bytesWritten;
		}
	}

	close(fd);

	bytesLeft = len;

	// Iterate until all encrypted content from server has been received into buffer and written to file
	// Adapted from own code used in assignments from CS372 assignment on TCP file transfer, originally referenced from Linux/C documentation on man7.org
	while(bytesLeft > 0) {
		// Must memset buffer each iteration
		memset(buffer, 0, sizeof(buffer));

		// Add contents to string and decrease remaining bytes accordingly
		int bytesRead = recv(socketFD, buffer, sizeof(buffer)-1, 0);
		bytesLeft -= bytesRead;

		// Error handling if read failed or read is done incorrectly
		if(bytesRead < 0) {
			error("Error reading file");
		}

		printf("%s", buffer);
	}

	// Close socket
	close(socketFD); 

	return 0;
}
