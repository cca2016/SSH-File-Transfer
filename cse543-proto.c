/***********************************************************************

   File          : cse543-proto.c

   Description   : This is the network interfaces for the network protocol connection.

   Last Modified : 2018
   By            : Trent Jaeger

***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-network.h"
#include "cse543-proto.h"
#include "cse543-ssl.h"


/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(hdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(hdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Get message encrypted (by encrypt) and put ciphertext 
                   and metadata for decryption into buffer
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - place to put ciphertext and metadata for 
                   decryption on other end
                : len - length of the buffer after message is set 
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
  unsigned char *ciphertext, *tag;
  unsigned char *iv;
  int clen=0, plen=0;
  
  /*perform encrypt*/
  tag=(unsigned char *) malloc(TAGSIZE);
  iv=(unsigned char *) malloc(16);
  memset(tag,0,TAGSIZE);
  memset(iv,0,16);
  clen=encrypt(plaintext, plaintext_len, (unsigned char *)NULL, 0, key, iv, ciphertext,tag);
  memcpy(buffer,ciphertext,clen); 
  memcpy(buffer+clen,iv,16);
  memcpy(buffer+clen+16,tag,TAGSIZE);

  *len=clen+TAGSIZE+16;
  return 0;

}



/**********************************************************************

    Function    : decrypt_message
    Description : Recover plaintext from ciphertext (by decrypt)
                   using metadata from buffer
    Inputs      : buffer - ciphertext and metadata - in format set by
                   encrypt_message
                : len - length of buffer containing ciphertext and metadata
                : key - symmetric key
                : plaintext - place to put decrypted message
                : plaintext_len - size of decrypted message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
  unsigned char *tag=(unsigned char *) malloc(TAGSIZE);
  unsigned char *iv=(unsigned char *) malloc(16);
  unsigned char *ciphertext=(unsigned char *) malloc(len-TAGSIZE-16);

  memset(tag,0,TAGSIZE);
  memset(iv,0,16);
  memset(ciphertext,0,len-TAGSIZE-16);

  memcpy(ciphertext,buffer,len-TAGSIZE-16);
  memcpy(iv,buffer+len-TAGSIZE-16,16);
  memcpy(tag,buffer+len-TAGSIZE,TAGSIZE);
 

  *plaintext_len = decrypt( ciphertext, len-TAGSIZE-16 , (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
  /* printf("plaintext:------------------------%d\n",*plaintext_len); */



  return 0;
}


/**********************************************************************

    Function    : extract_public_key
    Description : Create public key data structure from network message
    Inputs      : buffer - network message  buffer
                : size - size of buffer
                : pubkey - public key pointer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int extract_public_key( char *buffer, unsigned int size, EVP_PKEY **pubkey )
{
	RSA *rsa_pubkey = NULL;
	FILE *fptr;

	*pubkey = EVP_PKEY_new();

	/* Extract server's public key */
	/* Make a function */     
	fptr = fopen( PUBKEY_FILE, "w+" );
	if ( fptr == NULL ) {
		errorMessage("Failed to open file to write public key data");
		return -1;
	}

	fwrite( buffer, size, 1, fptr );
	rewind(fptr);

	/* open public key file */
	if (!PEM_read_RSAPublicKey( fptr, &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Cliet: Error loading RSA Public Key File.\n");
		return -1;
	}

	if (!EVP_PKEY_assign_RSA(*pubkey, rsa_pubkey))
	{
		errorMessage("Client: EVP_PKEY_assign_RSA: failed.\n");
		return -1;
	}

	fclose( fptr );
	return 0;
}


/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudorandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int generate_pseudorandom_bytes( unsigned char *buffer, unsigned int size)
{
   /* printf("before fake\n");  */
  /* RAND_pseudo_bytes(buffer,size); */
   // buffer=(unsigned char *)malloc (size);
   // memset(buffer,0,size);
   RAND_bytes(buffer,size); 
   /* BIO_dump_fp(stdout,(const unsigned char*) buffer,KEYSIZE); */
   /* printf("after fake,length of buffer is:\n");  */

  return 0;
}


/**********************************************************************

    Function    : seal_symmetric_key
    Description : Encrypt symmetric key using OpenSSL public key (call rsa_encrypt)
    Inputs      : key - symmetric key
                  keylen - symmetric key length in bytes
                  pubkey - public key
                  buffer - output buffer to store the encrypted key and 
                     and metadata for decrypting in unseal
    Outputs     : len if successful, -1 if failure

***********************************************************************/

int seal_symmetric_key( unsigned char *key, unsigned int keylen, EVP_PKEY *pubkey, char *buffer )
{
	unsigned int len = 0;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	unsigned char *ciphertext;

	len = rsa_encrypt(key, keylen, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );
        memcpy(buffer,ciphertext,48);
	memcpy(buffer+48,ek,256);
        memcpy(buffer+48+256,iv,16);
	len=len+256+16;
	return len;
       
}

/**********************************************************************

    Function    : unseal_symmetric_key
    Description : Decrypt symmetric key using OpenSSL private key (call rsa_decrypt)
    Inputs      : buffer - buffer containing the encrypted key and 
                     and metadata for decrypting in format determined
                     in seal_symmetric_key
                  len - length of buffer
                  privkey - private key 
                  key - symmetric key (plaintext from rsa_decrypt)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int unseal_symmetric_key( char *buffer, unsigned int len, EVP_PKEY *privkey, unsigned char **key )
{
         
 	 unsigned char *ek;
	 unsigned int ekl; 
 	 unsigned char *iv;
	 unsigned int ivl;
         unsigned char *ciphertext;
         
         ciphertext=(unsigned char*) malloc(48);
	 ek=(unsigned char *) malloc(256);
	 ekl=256;
         iv=(unsigned char *) malloc(16);
         ivl=16;
	 memcpy(ciphertext,buffer,48);
         memcpy(ek,buffer+48,256);
         memcpy(iv,buffer+48+256,16);
         rsa_decrypt(ciphertext, 48, ek, ekl, iv, ivl, key, privkey );
	 return 0;  
         
}


/* 

  CLIENT FUNCTIONS 

*/



/**********************************************************************

    Function    : client_authenticate
    Description : this is the client side of your authentication protocol
    Inputs      : sock - server socket
                  session_key - the key resulting from the exchange
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int client_authenticate( int sock, unsigned char **session_key )
{
  ProtoMessageHdr hdr;
  char block[MAX_BLOCK_SIZE];
  EVP_PKEY **key;

  /*send start authenticate  print:start*/
   ProtoMessageHdr hdrtmp;
   char a[]="start";
   unsigned int len=0;
   char *buffer;

   hdrtmp.msgtype=CLIENT_INIT_EXCHANGE;
   hdrtmp.length=strlen(a);
   send_message(sock,&hdrtmp,a);

   /*get public key from server*/
   wait_message(sock,&hdr,block,SERVER_INIT_RESPONSE);
   extract_public_key(block,hdr.length,&key);
   /* BIO_dump_fp(stdout,key,EVP_PKEY_bits(key)); */ 
   printf("Get %d bits public key from server!\n",EVP_PKEY_bits(key));

   /*send encrypted session key from fake-random*/
   printf("Sending session key...\n");
   *session_key=(unsigned char *) malloc(KEYSIZE);
   memset(*session_key,0,KEYSIZE);
   generate_pseudorandom_bytes(*session_key,KEYSIZE);
   printf("---------------------create pseudo session_key:--------------------\n"); 
   BIO_dump_fp(stdout,(const unsigned char*) *session_key,KEYSIZE);  
   printf("---------------------create pseudo session_key:--------------------\n"); 

   buffer=(char *) malloc (320);
   memset(buffer,0,320);
   len=seal_symmetric_key(*session_key, KEYSIZE, key, buffer );
   printf("-------------encrypted session key------[length is: %d]\n",len);
   BIO_dump_fp(stdout,buffer,len);
   printf("-------------encrypted session key------\n");
   hdr.msgtype=CLIENT_INIT_ACK; 
   hdr.length=len; 
   send_message(sock,&hdr,buffer); 

   
   unsigned char *buffer_from_ack=(unsigned char *)malloc (MAX_BLOCK_SIZE);
   unsigned char *buffer_return_ack=(unsigned char *)malloc (MAX_BLOCK_SIZE);
   unsigned int buffer_return_len=0;
   wait_message(sock,&hdr,buffer_from_ack,SERVER_INIT_ACK);
   decrypt_message(buffer_from_ack, hdr.length, *session_key, buffer_return_ack, &buffer_return_len);
   printf("buffer_return_len:%d\n",buffer_return_len);
   BIO_dump_fp(stdout,buffer_return_ack,buffer_return_len);
   printf("Client ACKs session key!\n");
   



}

/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sz - this is the size of the file to be read
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
	/* Local variables */
	int readBytes = 1, totalBytes = 0, fh;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
        char outblock[MAX_BLOCK_SIZE];
        /* memset(block,0,MAX_BLOCK_SIZE); */
	
	/* Read the next block */
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}

	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );

	/* Start transferring data */
	while ( (r->cmd == CMD_CREATE) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\r", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#if 1
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			/* Encrypt and send */
			printf("Sending file to server!\n");
			unsigned char *buffer_send=(unsigned char *)malloc(MAX_BLOCK_SIZE);
			memset(buffer_send,0,MAX_BLOCK_SIZE);
                    	encrypt_message(block,readBytes,key,buffer_send,&outbytes);
			printf("File length is:%d\n",outbytes);
			hdr.msgtype=FILE_XFER_BLOCK;
			hdr.length=outbytes;
			send_message(sock,&hdr,buffer_send);
		}
	}

	/* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int client_secure_transfer( struct rm_cmd *r, char *fname, char *address ) 
{
	/* Local variables */
	unsigned char *key;
	int sock;

	sock = connect_client( address );
	// crypto setup, authentication
	client_authenticate( sock, &key );
	// symmetric key crypto for file transfer
	transfer_file( r, fname, sock, key );
	// Done
	close( sock );

	/* Return successfully */
	return( 0 );
}

/* 

  SERVER FUNCTIONS 

*/

/**********************************************************************

    Function    : test_rsa
    Description : test the rsa encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_rsa( EVP_PKEY *privkey, EVP_PKEY *pubkey )
{
	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *plaintext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	printf("*** Test RSA encrypt and decrypt. ***\n");

	len = rsa_encrypt( (unsigned char *)"help me, mr. wizard!", 20, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, len);
#endif

	len = rsa_decrypt( ciphertext, len, ek, ekl, iv, ivl, &plaintext, privkey );

	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : test_aes
    Description : test the aes encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_aes( )
{
	int rc = 0;
	unsigned char *key;
	unsigned char *ciphertext, *tag;
	unsigned char *plaintext;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0, plen = 0;
	unsigned char msg[] = "Help me, Mr. Wizard!";
	unsigned int len = strlen(msg);

	printf("*** Test AES encrypt and decrypt. ***\n");

	/* make key */
	key= (unsigned char *)malloc( KEYSIZE );
	/* demonstrate with fixed key - don't do this in real systems */
	memcpy( key, "ABCDEFGH_IJKLMNOabcdefgh_ijklmno", KEYSIZE );  
	assert( rc == 0 );

	/* perform encrypt */
	ciphertext = (unsigned char *)malloc( len );
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( msg, len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= len ));

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);
#endif

	/* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
	assert( plen > 0 );

	/* Show the decrypted text */
#if 0
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
#endif
	
	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : server_protocol
    Description : server side of crypto protocol
    Inputs      : sock - server socket
                  pubfile - public key file name
                  privkey - private key value
                  enckey - the key resulting from the protocol
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

/*** YOUR_CODE ***/
int server_protocol( int sock, char *pubfile, EVP_PKEY *privkey, unsigned char **enckey )
{
  FILE *fptr;
  ProtoMessageHdr hdr;
  RSA *rsa_pubkey=NULL;
  unsigned char **buffer;

  char tmp[MAX_BLOCK_SIZE];
  wait_message(sock,&hdr,&tmp,CLIENT_INIT_EXCHANGE); 
  /* printf("total length is:[%d]\n",strlen(tmp)); */
  
  printf("Get start request,please %c%c%c%c%c\n",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4]);
  
  /*send public key*/
  printf("Sending public key to client...\n");
  hdr.msgtype=SERVER_INIT_RESPONSE;
  hdr.length=buffer_from_file(pubfile,&buffer);
  printf("pubkey len is ...[%d]\n ",hdr.length);
  send_message(sock,&hdr,buffer);
  printf("Send public key successfully!\n");
  
  printf("Starting receive encrypted session_key\n");
  unsigned char tmp2[320];
  wait_message(sock,&hdr,&tmp2,CLIENT_INIT_ACK);
  BIO_dump_fp(stdout,tmp2,hdr.length);
  unsigned int len=hdr.length;

  printf("Decrypt the session_key-----------------------\n");
  unsigned char *result;
  result=(unsigned char *) malloc(KEYSIZE);
  unseal_symmetric_key(tmp2, len, privkey, &result); 
  BIO_dump_fp(stdout,result,KEYSIZE);

  

  unsigned char msg[]="I get the session key!";
  printf("Sending a message tell client about the session key!\n");
  unsigned char *buffer_for_ack=(unsigned char *)malloc (MAX_BLOCK_SIZE);
  memset(buffer_for_ack,0,MAX_BLOCK_SIZE);
  unsigned int buffer_len=0;
  encrypt_message(msg,strlen(msg),result, buffer_for_ack, &buffer_len);
  BIO_dump_fp(stdout,buffer_for_ack,buffer_len);

  hdr.msgtype=SERVER_INIT_ACK;
  hdr.length=buffer_len;
  send_message(sock,&hdr,buffer_for_ack);
  
  /* memcpy(enckey,result,KEYSIZE); */
  *enckey=(unsigned char *)calloc(KEYSIZE,sizeof(char));
  memcpy(*enckey,result,KEYSIZE);
 

  
  
  
  
  
  
 
  
  
}


/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the AES session key used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];

	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );
	
	unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
	char *fname = (char *)malloc( size );
	/* open file */
	if ( r->type == TYP_DATA_SHARED ) {
		
		snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
		if ( (fh=open( fname, O_WRONLY|O_CREAT, 0700)) > 0 );
		else assert( 0 );
	}
	else assert( 0 );

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {
		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", fname );
		while (!done)
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				assert( rc  == 0 );
				write( fh, plaintext, outbytes );

#if 1
				printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif

				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		//	     exit( -1 );
	}

	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : pubkey - public key of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer( char *privfile, char *pubfile )
{
	/* Local variables */
	int server, errored, newsock;
	RSA *rsa_privkey = NULL, *rsa_pubkey = NULL;
	RSA *pRSA = NULL;
	EVP_PKEY *privkey = EVP_PKEY_new(), *pubkey = EVP_PKEY_new();
	fd_set readfds;
	unsigned char *key;
	FILE *fptr;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	/* Connect the server/setup */
	server = server_connect();
	errored = 0;

	/* open private key file */
	fptr = fopen( privfile, "r" );
	assert( fptr != NULL);
	if (!(pRSA = PEM_read_RSAPrivateKey( fptr, &rsa_privkey, NULL, NULL)))
	{
		fprintf(stderr, "Error loading RSA Private Key File.\n");

		return 2;
	}

	if (!EVP_PKEY_assign_RSA(privkey, rsa_privkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr ); 

	/* open public key file */
	fptr = fopen( pubfile, "r" );
	assert( fptr != NULL);
	if (!PEM_read_RSAPublicKey( fptr , &rsa_pubkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign_RSA( pubkey, rsa_pubkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr );

	// Test the RSA encryption and symmetric key encryption
	test_rsa( privkey, pubkey );
	test_aes();

	/* Repeat until the socket is closed */
	while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* Do the protocol, receive file, shutdown */
				server_protocol( newsock, pubfile, privkey, &key );
				receive_file( newsock, key );
				close( newsock );
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}

