#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <resolv.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <unistd.h>   
#include <netdb.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>  
#include <netinet/in.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL -1
char** _hostname;
int _portOpen, _portConnect;

//Used by the Client method of Peer-to-Peer application for connecting to Open socket
int OpenConnection(const char *hostname, int port) { 
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;
	if ( (host = gethostbyname(hostname)) == NULL ) {
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
		close(sd);
		perror(hostname);
		abort();
	}
	return sd;
}

//Used by the Server method of Peer-to-Peer application for Opening a socket
int _OpenListener(int port) {   
	int sd;
	struct sockaddr_in addr;
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 ) {
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

//Used by the Client method of Peer-to-Peer application for Initializing the SSL context
SSL_CTX* InitCTX(void) {   
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms(); 
	SSL_load_error_strings();
	method = TLSv1_2_client_method(); //Creating new client method instance
	ctx = SSL_CTX_new(method); //Creating new context from client method
	if ( ctx == NULL ) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

//Used by the Server method of Peer-to-Peer application for Initializing the SSL context
SSL_CTX* InitServerCTX(void) { 
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();  
	method = TLSv1_2_server_method(); //creating new server method instance
	ctx = SSL_CTX_new(method); //creating new context from server method
	if ( ctx == NULL ) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

//Used by the Server method of Peer-to-peer application for Loading the certificate file
void _LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) { //setting the local certificate from .cert.pem
		ERR_print_errors_fp(stderr);
		abort();
	}
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) { //setting the private key from KeyFile
		ERR_print_errors_fp(stderr);
		abort();
	}
	if ( !SSL_CTX_check_private_key(ctx) ) { //verifying the private key
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

//Used by the Client method of Peer-to-peer application for Printing-out the certificate file
void ShowCerts(SSL* ssl) {   
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);
	if ( cert != NULL ) {
		printf("\nServer certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line); 
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("Info: No client certificates configured.\n");
}

//Used by the Server method of Peer-to-peer application for Receiving and Printing-out the message recieved from Peer
void _Servlet(SSL* ssl) {
	char buf[1024];
	int bytes;
	if ( SSL_accept(ssl) == FAIL )  
		ERR_print_errors_fp(stderr);
	else {
		bytes = SSL_read(ssl, buf, sizeof(buf)); //Reading the message recieved from Peer's client
		if ( bytes > 0 ) {
			buf[bytes] = 0;
			printf("\tMessage recieved: %s\n", buf);
		}
		else
			ERR_print_errors_fp(stderr);
	}
}

//Server method of Peer-to-peer application for Creating and accepting SSL socket
void *server(void* tid) {  
	SSL_CTX *ctx;
	int server;
	int portnum = _portOpen;
	int sd;
	SSL_library_init();
	ctx = InitServerCTX(); //Initializing SSL
	_LoadCertificates(ctx, "mycert.pem", "mycert.pem"); //Loading certificate file
	server = _OpenListener(portnum); //creating server socket
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	SSL *ssl;
	int client = accept(server, (struct sockaddr*)&addr, &len);
//	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client);
	while (1) { 
		_Servlet(ssl);
	}
	sd = SSL_get_fd(ssl);       
	SSL_free(ssl); //releasing the SSL state
	close(sd);     
	close(server); //closing the server socket
	SSL_CTX_free(ctx); //releasing the context
}

//Client method of Peer-to-peer application for connecting to SSL socket
void *client(void* tid) {
	printf("Waiting to connect..\n");
	usleep(10000000); //Sleeping for 10 seconds to wait for Peer's server to start
	int server;
	char *hostname = _hostname;
	int portnum = _portConnect;	
	SSL_CTX *ctx;
	SSL *ssl;
	SSL_library_init();
	ctx = InitCTX();
	server = OpenConnection(hostname, portnum);
	ssl = SSL_new(ctx); //creating a new SSL connection state
	SSL_set_fd(ssl, server);    
	if ( SSL_connect(ssl) == FAIL ) 
		ERR_print_errors_fp(stderr);
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
		printf("\nYou can start the chat: \n");        
		while(1) {
			char msg[50];
			scanf("%s",msg);
			SSL_write(ssl, msg, strlen(msg));
		}
		SSL_free(ssl);       
	}
	close(server);         
	SSL_CTX_free(ctx);  
	return 0;
}

int main(int argc, char** argv) {
	void *status;
	int rc2;
	if ( argc != 4 ) {
		printf("Usage: %s <hostname> <port of server> <certificate_file_name> <port of client>\n", argv[0]);
		exit(0);
	}
	_hostname = argv[1];
	_portConnect = atoi(argv[2]);
	_portOpen = atoi(argv[3]); 
	if ( _portConnect == _portOpen ) {
		printf("Both port numbers can not be same!");
		exit(0);
	}
	pthread_attr_t attr;    
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_t pthreads[2];
	int tid[2];
	for(int i=0; i<2; i++) {
		tid[i] = i;
		if (i == 0)
			rc2 = pthread_create(&pthreads[i], NULL,server, &tid[i]);
		else
			rc2 = pthread_create(&pthreads[i], NULL,client, &tid[i]);
		if (rc2)
			exit(-1);
	}
	pthread_attr_destroy(&attr);
	for(int i=0;i<2;i++) {
		rc2=pthread_join(pthreads[i], &status);
		if (rc2)
			exit(-1);
	}
	pthread_exit(NULL);
	return 0;
}
