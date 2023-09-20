//////////////
//   Alice  //
/////////////
/***********************************************************************
 *  Toy Steam Cipher Implementation   *
 ***********************************************************************
 *Description:  //alice pov
 			1. Alice reads message from "Message.txt" file
 			2. Alice reads shared seed from "SharedSeed.txt" file.
 			3. Alice generates the secret key based on the shared seed by ChaCha20 PRNG.
 			4. Alice writes the Hex format of key in file neamed "Key.txt".
 			5. Alice XORs message with secret key to obtain ciphertext.
 		  	6. Alice writes the hex format of cipher in ciphertext.txt.
 		  	7. Alice sends ciphertext to Bob via zeroMQ.
 		  	8. Alice waits for acknowledgement from Bob.
 		//bob pov
 			1. bob receives cipher from zmq
 			2. bob reads shared seedfrom "SharedSeed.txt" file.
 			3. bob genereates secret ckey based on PRNG chacha20.
 			4. bob xors recieved cipher text with secret key, obtaining plaintxt.
 			5. bob writes decrypted plaintext in file named "Plaintext.txt".
 			6. bob hashes plaintext with sha256 and places in file named "Hash.txt"
 			7. bob sends hash over zmq to alice as acknowledgement.
 		//alice pov
 			9.compare acknowledgement from bob.
 
 
 *Compile:          gcc alice.c -ltomcrypt -lzmq -o alice
 * 
 *Run example:      ./alice Message1.txt SharedSeed1.txt
 *
 *Documentation:    Libtomcrypt Manual Chapter 8 section 1
 *
 * Created By:      << Alexander Ashmore...CYPT_Theory class's functions/code by Saleh Darzi >>
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
void Send_via_ZMQ(unsigned char send[], int sendlen);
unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit);
int writeHexToFile(const char* fileName, unsigned char* data, int length);


/*************************************************************
						M A I N
**************************************************************/
int main (int argc, char* argv[])
{   
//---1. Alice reads the message form "Message.txt" file    
    printf("Getting the Message from File . . .\n");
    int message_length = 0;
    unsigned char* message = Read_File(argv[1], &message_length); //"Message.txt"
	printf("Message: %s", message);
    printf("Message Length: %d", message_length);
    
    printf("\n==================================================\n");


//---2. Alice reads shared seed from "SharedSeed.txt" file.
    printf("Getting the Seed from File . . .\n");
    int seed_length = 0;
    unsigned char* seed = Read_File(argv[2], &seed_length); //"SharedSeed.txt"
	printf("Seed: %s\n", seed);
    printf("Given Seed Length: %d\n", seed_length);
    


//---3. Alice generates the secret key based on the shared seed by ChaCha20 PRNG.
    printf("Calling the PRNG function . . .\n");
    unsigned char* key = PRNG(seed, seed_length, seed_length);
    Show_in_Hex("Generated Key", key, seed_length); 

    printf("==================================================\n");
    
    
//---4. Alice writes the Hex format of key in file neamed "Key.txt".
    if (writeHexToFile("Key.txt", key, seed_length)) {
        printf("Key written to Key.txt successfully.\n");
    } else {
        printf("Failed to write the key to Key.txt.\n");
    }   
    
//---5. Alice XORs message with secret key to obtain ciphertext.
    unsigned char* ciphertext = malloc(message_length);
    for (int i = 0; i < message_length; i++) {
        ciphertext[i] = message[i] ^ key[i];
    }


//---6. Alice writes the hex format of cipher in ciphertext.txt.
    if (writeHexToFile("Ciphertext.txt", ciphertext, message_length)) {
        printf("cipher written to Ciphertext.txt successfully.\n");
    } else {
        printf("Failed to write the Ciphertext.txt.\n");
    }
    printf("\n==================================================\n");

//---7. Alice sends ciphertext to Bob via zeroMQ.
    int sendlen = message_length;
    Send_via_ZMQ(ciphertext, sendlen);
    printf("Ciphertext sent to Bob via ZeroMQ.\n");


//---8. Alice waits for acknowledgement from Bob.
	unsigned char* receivedAck = malloc(32); // Assuming acknowledgment is 32 bytes (SHA-256 hash size)
	void *context = zmq_ctx_new();
	void *receiver = zmq_socket(context, ZMQ_REP); // Create a reply socket to receive acknowledgment
	
	zmq_bind(receiver, "tcp://*:5556"); // Binding to new port....pretty sure i went about this wrong making new port...
	printf("Waiting for acknowledgment from Bob...\n");
	
	
//---9.compare acknowledgement from bob.
	zmq_recv(receiver, receivedAck, 32, 0); // Receive the acknowledgment from Bob
	// Calculate the hash of the original message
	unsigned char* originalHash = Hash_SHA256(message, message_length);

	// Compare received acknowledgment with the hash of the original message
	int acknowledgmentSuccessful = memcmp(receivedAck, originalHash, 32) == 0;

	// Write the result to Acknowledgment.txt
	FILE* acknowledgmentFile = fopen("Acknowledgment.txt", "w");
	if (acknowledgmentFile) {
	    if (acknowledgmentSuccessful) {
		fprintf(acknowledgmentFile, "Acknowledgment Successful.");
	    } else {
		fprintf(acknowledgmentFile, "Acknowledgment Failed.");
	    }
	    fclose(acknowledgmentFile);
	} else {
	    printf("Error doing Acknowledgment.txt\n");
	}

	// cleansing our souls from ZeroMQ resources. god bless this cursed thing
	zmq_close(receiver);
	zmq_ctx_destroy(context);
	
	printf("\n");
	printf("Acknowledgment properly made.\n");




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
        printf("error opening file for w.");
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
    hash_state md;                                                         //LibTomCrypt structure for hash
    sha256_init(&md);                                                      //Initializing the hash set up
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
    zmq_connect (requester, "tcp://localhost:5555");		    		//make outgoing connection from socket
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
   	int rc = zmq_bind (responder, "tcp://*:5556");	                                	//make outgoing connection from socket
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
