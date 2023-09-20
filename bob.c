//////////////
//   Bob    //
/////////////
/***********************************************************************
 *  Toy Steam Cipher Implementation *
 ***********************************************************************
 *Description:      
 		    1. Bob receives the cipher text from Alice via ZMQ
 		    2. Bob reads shared seed from "SharedSeed.txt
 		    3. Bob genereates secret key from shared seed using PRNG, chacha20.
 		    4. Bob XORs reveived cipher text with secret key to obtain plaintext.
 		    5. Bob writes the decrypted plaintext in a file name "Plaintext.txt"
 		    6. Bob hashes plaintext using sha256.
 		    7. Bob sends hash thru ZMQ to alice as acknowledgement.
 * 
 * 
 *
 *Compile:          gcc bob.c -ltomcrypt -lzmq -o bob
 *
 *Run:              ./bob
 *
 *Documentation:    Libtomcrypt Manual Chapter 8 section 1
 *
 * Created By:      << SAlexander Ashmore...CYPT_Theory class's functions/code by Saleh Darzi >>
_______________________________________________________________________________*/

//Header Files
#include <stdlib.h>
#include <stdio.h>
#include <libtomcrypt/tomcrypt.h>
#include <zmq.h>

//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
unsigned char* Hash_SHA256(unsigned char input[], unsigned long inputlen);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit);
void Send_via_ZMQ(unsigned char send[], int sendlen);
int writeHexToFile(const char* fileName, unsigned char* data, int length);


/*************************************************************
						M A I N
**************************************************************/
int main (int argc, char* argv[])
{   

// ---1. Bob receives ciphertext from Alice via ZeroMQ.
    void* context = zmq_ctx_new();
    void* responder = zmq_socket(context, ZMQ_REP); // Create a reply socket to receive ciphertext
    zmq_bind(responder, "tcp://*:5555");           // Binding to the port
    printf("Waiting for ciphertext from Alice...\n");

    int max_ciphertext_length = 1024; // Maximum expected ciphertext size (adjust as needed)
    unsigned char receivedCiphertext[max_ciphertext_length];
    
    // Receive the ciphertext
    int received_length = zmq_recv(responder, receivedCiphertext, max_ciphertext_length, 0);


    // ---2. Bob reads shared seed from "SharedSeed.txt" file.
    printf("Getting the Seed from File . . .\n");
    int seed_length = 0;
    unsigned char* seed = Read_File(argv[1], &seed_length); // "SharedSeed.txt"
    printf("Seed: %s\n", seed);
    printf("Seed Length: %d\n", seed_length);


    // ---3. Bob generates the secret key based on PRNG (ChaCha20).
    printf("Calling the PRNG function . . .\n");
    unsigned char* key = PRNG(seed, seed_length, seed_length); // Assuming a 32-byte key
    Show_in_Hex("Generated Key", key, seed_length); // Adjust size accordingly
    printf("\n==================================================\n");

    // ---4. Bob XORs received ciphertext with the secret key to obtain plaintext.
    //int ciphertext_length = 32; // Adjust size accordingly
    size_t ciphertext_length = received_length;
    //printf("Size of receivedCiphertext array: %zu\n", ciphertext_length);
    
    unsigned char* plaintext = malloc(ciphertext_length); // Adjust size accordingly
    for (int i = 0; i < ciphertext_length; i++) {
        plaintext[i] = receivedCiphertext[i] ^ key[i];
    }
    printf("\n==================================================\n");

    // ---5. Bob writes decrypted plaintext in a file named "Plaintext.txt".
    FILE* plaintxtFile = fopen("Plaintext.txt", "wb");
    if (plaintxtFile) {
        fwrite(plaintext, 1, ciphertext_length, plaintxtFile); // Adjust size accordingly
        fclose(plaintxtFile);
        printf("plaintext written successfully\n");
    } else {
        printf("Error writing Plaintext.txt\n");
    }
 

    // ---6. Bob hashes plaintext with SHA-256 and places it in a file named "Hash.txt".
    unsigned char* hash = Hash_SHA256(plaintext, ciphertext_length); // Adjust size accordingly
    if (writeHexToFile("Hash.txt", hash, 32)) {
        printf("Hash written to Hash.txt successfully.\n");
    } else {
        printf("Failed to write the Hash to Hash.txt.\n");
    }    
    printf("\n==================================================\n");

    // ---7. Bob sends the hash over ZeroMQ to Alice as acknowledgment.
    Send_via_ZMQ(hash, 32); // SHA-256 hash size is 32 bytes
    printf("Acknowledgment sent to Alice via ZeroMQ.\n");

    printf("==============The End========================\n");

    return 0;


}

/*************************************************************
					F u n c t i o n s
**************************************************************/
//converts to readable format in files.
int writeHexToFile(const char* fileName, unsigned char* data, int length) {
    FILE* file = fopen(fileName, "w");
    if (file == NULL) {
        printf("Error opening file for w.");
        return 0;
    }

    for (int i = 0; i < length; i++) {
        fprintf(file, "%02x", data[i]);
    }

    fclose(file);
    return 1;
}
/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

/*============================
        SHA-256 Fucntion
==============================*/
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash_result = (unsigned char*) malloc(inputlen);
    //int err;
    hash_state md;                                                          //LibTomCrypt structure for hash
    sha256_init(&md);                                                       //Initializing the hash set up
    sha256_process(&md, (const unsigned char*)input, inputlen);            //Hashing the data given as input with specified length
    sha256_done(&md, hash_result);                                         //Produces the hash (message digest)
    
    return hash_result;
}

/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex (char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen)
{
    int err;
    unsigned char *pseudoRandomNumber = (unsigned char*) malloc(prnlen);

    prng_state prng;                                                           //LibTomCrypt structure for PRNG
    if ((err = chacha20_prng_start(&prng)) != CRYPT_OK){                       //Sets up the PRNG state without a seed
        printf("Start error: %s\n", error_to_string(err));
    }					                
    if ((err = chacha20_prng_add_entropy(seed, seedlen, &prng)) != CRYPT_OK) {      //Uses a seed to add entropy to the PRNG
        printf("Add_entropy error: %s\n", error_to_string(err));
    }	            
    if ((err = chacha20_prng_ready(&prng)) != CRYPT_OK) {                      //Puts the entropy into action
        printf("Ready error: %s\n", error_to_string(err));
    }
    chacha20_prng_read(pseudoRandomNumber, prnlen, &prng);                     //Writes the result into pseudoRandomNumber[]
    
    if ((err = chacha20_prng_done(&prng)) != CRYPT_OK) {                       //Finishes the PRNG state
        printf("Done error: %s\n", error_to_string(err));
    }

    return (unsigned char*)pseudoRandomNumber;
}

/*============================
        Sending via ZeroMQ 
==============================*/
void Send_via_ZMQ(unsigned char send[], int sendlen)
{
    void *context = zmq_ctx_new ();					        //creates a socket to talk to Bob
    void *requester = zmq_socket (context, ZMQ_REQ);		    		//creates requester that sends the messages
    printf("Connecting to Bob and sending the message...\n");
    zmq_connect (requester, "tcp://localhost:5556");		    		//make outgoing connection from socket
    zmq_send (requester, send, sendlen, 0);			    	    	//send msg to Bob
    zmq_close (requester);						        //closes the requester socket
    zmq_ctx_destroy (context);					                //destroys the context & terminates all 0MQ processes
}

/*============================
        Receiving via ZeroMQ 
==============================*/
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit) 
{
	void *context = zmq_ctx_new ();			        	                                 //creates a socket to talk to Alice
    void *responder = zmq_socket (context, ZMQ_REP);                                   	//creates responder that receives the messages
   	int rc = zmq_bind (responder, "tcp://*:5555");	                                	//make outgoing connection from socket
    int received_length = zmq_recv (responder, receive, limit, 0);	                  	//receive message from Alice
    unsigned char *temp = (unsigned char*) malloc(received_length);
    for(int i=0; i<received_length; i++){
        temp[i] = receive[i];
    }
    *receivelen = received_length;
    //printf("Received Message: %s\n", receive);
    //printf("Size is %d\n", received_length-1);
    return temp;
}
//__________________________________________________________________________________________________________________________

