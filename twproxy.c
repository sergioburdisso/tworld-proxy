/*
* Author: Burdisso Sergio
*/
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include "lib/sha1.h"
#include "lib/base64.h"

#define _MAX_CLIENT				64
#define _BUFFER_SIZE			16*1024//16KB
#define _DEFAULT_PORT			80
#define _QUEUE_LENGTH_			16
#define _WS_SPECIFICATION_GUID	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef enum _bool {false=0, true=1} bool;
typedef struct sockaddr_in sockaddr_in;

// NOTE: fd stands for File Descriptor which is basically an index for a kernel-resident array data structure
// associated with this process used to keep track of all the buffer-based resources that the process is working with
typedef struct _dual_sock_conn{
	int			fdw;			// file descriptor assigned to the web socket
	int			fdu;			// file descriptor assigned to the user socket
	bool		fdwHandled_flag;// flag used to indicate if the fdw is new at this node (and its events were previously handled)
	bool		fduHandled_flag;// flag used to indicate if the fds is new at this node (and its events were previously handled)
	char*		wtouBuffer; 	// buffer used to send data from WebSocket to user socket
	char*		utowBuffer;		// buffer used to send data from user socket to WebSocket
	uint16_t	utowLen;		// number of bytes to be send from WebSocket to user socket
} dual_sock_conn;

//for select() system call
int		fdMax;						// stores the biggest file descriptor assigned to this process so far
int		fdsReady;					// number of fds that have changed
fd_set	fdReadSocks, fdWriteSocks;	// set of fds we are going to wait for events to happen --write/read

//Server socket
int			fdServerSock;			// fd for the server socket (i.e the listen()-er socket)
sockaddr_in	serverAddress;			// address the listen()-er socket is going to be binded to

//Connections
dual_sock_conn conns[_MAX_CLIENT];	// array of paired connections (webSocket, userSocket) needed for the 1 to 1 map

//WebSocket handshake
char secWebsocketAccept[29];		// Stores the Base64(SHA-1(fullWebSocketKey))
regex_t regex_wsInitialMsg;			// compiled regular expression for detecting websocket handshake from web browser
char handshakeMessage[126];			// Stores the full handshake message to be sent to the WebSocket
char fullWebSocketKey[60];			// Sec-WebSocket-Key base64-encoded value (when decoded, is 16 bytes in length)
unsigned char* KeyHash;				// Stores the SHA1(fullWebSocketKey) 160 bits value for the server handshake replay
regmatch_t matchs[4];				// stores the substrings matching the subpatterns inside parenthesis

//program options
bool		_WS_TO_US_FORWARDING = true;
bool		_VERBOSE_MODE = false;
uint16_t	_PORT = 0;


void displayHelp(char const* programName){
	printf(
		"Usage: %s [OPTION]...\n\n"
		"OPTIONS:\n\n"
		"-p, --port <NUM>       Allow you to define the port number your Tileworld Proxy\n"
		"                       will listen on.  The port  number must be  between 1 and\n"
		"                       65535.  If no value is provided, this property is set to\n"
		"                       the default value of %d\n\n"
		"-v, --verbose          Allow the application to display trace information\n\n"
		"-n, --no-forwarding    Disable forwarding data coming from  the 3D Tileworld to\n"
		"                       the user program\n\n"
		"-?, --help             Display this help and exit\n\n",
		programName, _DEFAULT_PORT
	);
	exit(EXIT_SUCCESS);
}

//is it an error?
void checkIfError(int value, char const* origin, char const* msg){
	if (value < 0){
		//fprintf (stderr, "%s: error:\n\t%s\n\n", origin, (msg!=NULL)? msg: "an unknown error has occurred");
		printf("%s: error: %s.\n\n", origin, (msg!=NULL)? msg: "an unknown error has occurred");
		exit(EXIT_FAILURE);
	}
}

//"tells the Kernel that this process does not need to wait for (block until) this socket to complete reading/writing"
void setNonBlockingFlag(int fdSock){
	int flags;

	//getting the flags associated with the socket
	//from the Kernel's File Descriptors array assigned to this process
	//using fdSock as index
	flags = fcntl(fdSock,F_GETFL);
	if (flags < 0) {
		perror("fcntl: error: cant get the socket flags (F_GETFL) from the kernel-resident file descriptors array related to this process");
		exit(EXIT_FAILURE);
	}

	//setting the O_NONBLOCK bit to one
	flags = (flags | O_NONBLOCK);
	if (fcntl(fdSock,F_SETFL,flags) < 0) {
		perror("fcntl: error: cant set the socket flags (F_SETFL) in the kernel-resident file descriptors array related to this process");
		exit(EXIT_FAILURE);
	}
}

void resetAndSetFileDescriptorSets(){
	int i;

	//1) Initializes the file descriptor sets to have zero bits for all file descriptors
	FD_ZERO( &fdReadSocks  );
	FD_ZERO( &fdWriteSocks );

	//2) adding the fds of the sockets we want to be woken up by (whenever I/O events happen) to the fd sets
	//-> listener socket
	FD_SET(fdServerSock, &fdReadSocks);

	//-> connection sockets
	//NOTE:since _MAX_CLIENT is expected to be a small number, I've decided not to
	//use any other data structure other than simple-plain arrays and loop _completely_
	//through them
	for (i=0; i < _MAX_CLIENT; ++i){
		if ( conns[i].fdw ){
			conns[i].fduHandled_flag = conns[i].fdwHandled_flag = false;

			FD_SET(conns[i].fdw, &fdReadSocks );
			FD_SET(conns[i].fdw, &fdWriteSocks);
		}

		if ( conns[i].fdu ){
			FD_SET(conns[i].fdu, &fdReadSocks );
			FD_SET(conns[i].fdu, &fdWriteSocks);
		}
	}
}

void closeWS(dual_sock_conn* sockConn){
	if (_VERBOSE_MODE) printf("[socket fd:%d]\tother side closed the socket\n", sockConn->fdw);

	close(sockConn->fdw);

	if (sockConn->fdu){
		char const* msg = "error('Tileworld instance was closed by the other side').\n";
		memcpy( sockConn->wtouBuffer, msg, strlen(msg) );
	}

	sockConn->fdw = sockConn->utowBuffer[0] = 0;
}

void newConnectionEventHandler(){
	int i, fdConnect;

	checkIfError(
		fdConnect = accept(fdServerSock, NULL/*client address (not necessary)*/, NULL),
		"socket: connect",
		"couldn't create the socket for a new connection"
	);

	if (fdConnect > fdMax)
		fdMax = fdConnect;

	// assumes that it is not a webSocket and adds it to the conns list
	// (this will change later on in case the data received from this socket
	// corresponds to that of the WebSocket Protocol (i.e. the WebSocket handshake))
	for (i=0; i < _MAX_CLIENT; ++i){
		if ( !conns[i].fdw && !conns[i].fdu ){

			conns[i].fdu = fdConnect;
			//creating buffer on demand
			if (conns[i].wtouBuffer == NULL){
				conns[i].wtouBuffer = (char *)calloc(sizeof(char), _BUFFER_SIZE);
				conns[i].utowBuffer = (char *)calloc(sizeof(char), _BUFFER_SIZE);
			}

			if (_VERBOSE_MODE) printf("[server socket]\tnew connection accepted [new socket fd:%d]\n", fdConnect);
			break;
		}
	}

	if (i >= _MAX_CLIENT){
		char const* msg = "error: server is full or too busy";

		perror("[server socket]\tnew connection: no room left for a new client");

		write(fdConnect, msg, strlen(msg)+1);//send
		close(fdConnect);
	}else
		setNonBlockingFlag(fdConnect);
}

void onWSReceiveEventHandler(dual_sock_conn* sockConn){
	char			buffer[_BUFFER_SIZE];
	uint64_t		payloadLength;
	unsigned int	i, bytesRecv;
	unsigned char	iMaskingKey, iPayloadData;

	if (_VERBOSE_MODE) printf("[socket fd:%d]\tnew data from this WebSocket was received\n", sockConn->fdw);

	checkIfError(
		bytesRecv = recv(sockConn->fdw, buffer, _BUFFER_SIZE, 0),
		"socket: recv",
		"couldn't receive data"
	);

	// if the other side closed the socket
	if (bytesRecv == 0)
		closeWS(sockConn);
	else if (_WS_TO_US_FORWARDING) {
		buffer[bytesRecv] = 0;

		if (_VERBOSE_MODE) printf("[socket fd:%d]\tdata is:\n%s\n", sockConn->fdw, buffer);

		//if this websocket doesn't have a user to exchange data with, try to find a free user for it
		if (!sockConn->fdu){
			for (i=0; i < _MAX_CLIENT; ++i)
				//if a user is waiting for a web socket!
				if ( !conns[i].fdw && conns[i].fdu ){
					conns[i].fdwHandled_flag = true; //flag to know that this ws is new at this i-th position and its ready-to-read event is already handled

					conns[i].fdw = sockConn->fdw;
					sockConn->fdw = 0;
					sockConn = &conns[i];
					break;
				}
		}
		
		//WEBSOCKET MESSAGE (see section 5 "Data Framing" from the RFC 6455) 
		
		//lookup the OpCode
		switch ( buffer[0]&0x0F ){

			case 1: // Text frame
				iMaskingKey = 2;

				switch (buffer[1]&0x7F/*Payload len*/){
					case 126:
						payloadLength = ntohs( *(uint16_t *)&buffer[2] );
						iMaskingKey += 2;// 16 bits = 2 bytes
						break;
					case 127:
						payloadLength = /*ntohll*/ntohl( *(uint64_t *)&buffer[2] );
						iMaskingKey += 8;// 64 bits = 8 bytes
						break;
					default:
						payloadLength = buffer[1]&0x7F;
				}
				iPayloadData = iMaskingKey + 4;// 4 bytes = 32 bits

				//IF MASK bit
				if (buffer[1]&0x80)
					//unmasking the receive payload data [RFC 6455 5.3]
					for (i=0; i < payloadLength; ++i)
						buffer[iPayloadData+i] = buffer[iPayloadData+i] ^ buffer[iMaskingKey + i%4];
				/*else
					error "client messages must be masked*/

				buffer[iPayloadData + payloadLength] = 0;

				//sending data to the web socket asynchronously
				if (sockConn->fdu){
					unsigned int offset = strlen(sockConn->wtouBuffer + 1);
					char head = sockConn->wtouBuffer[offset];

					//if FIN bit is 1
					if (buffer[0]&0x80){
						if (offset == 0)
							memcpy(sockConn->wtouBuffer, buffer + iPayloadData, payloadLength);
						else{
							memcpy(sockConn->wtouBuffer + offset, buffer + iPayloadData, payloadLength);
							sockConn->wtouBuffer[0] = head;
						}
						sockConn->wtouBuffer[offset + payloadLength] = 0;
					}else
					//if FIN bit is 0

						if (offset == 0){
							memcpy(sockConn->wtouBuffer + 1, buffer + iPayloadData + 1, payloadLength-1);
							sockConn->wtouBuffer[payloadLength] = buffer[iPayloadData];
							sockConn->wtouBuffer[payloadLength + 1] = 0;
						}else{
							memcpy(sockConn->wtouBuffer + offset, buffer + iPayloadData, payloadLength);
							sockConn->wtouBuffer[offset + payloadLength] = head;
							sockConn->wtouBuffer[offset + payloadLength+ 1] = 0;
						}
				}else
					if (_VERBOSE_MODE) printf("[socket fd:%d]\tno user socket to send data to\n", sockConn->fdw);
				break;

			case 8: //Close frame
				closeWS(sockConn);
				break;

			default:{
				char const* reasonMsg = "received type of data cannot be accepted (only text data is accepted)";
				//Close Frame (Data type not allowed)
				sockConn->utowBuffer[0] = 0x88;//1000 1000 i.e FIN-bit 0 0 0 Opcode(4 bits)

				//Payload len
				*(uint16_t *)&sockConn->utowBuffer[2] = htons( 1003 );//Status Codes (see RFC 6455 7.4.1. "Defined Status Codes")
				sockConn->utowBuffer[1] = (unsigned char)(strlen(reasonMsg) + 2);

				sockConn->utowLen = 2 + sockConn->utowBuffer[1];

				//sending the close frame
				memcpy(sockConn->utowBuffer + 4, reasonMsg, sockConn->utowBuffer[1] - 1);
				}
				break;
		}//switch
	}//if at least one byte was received 
}

void onUSReceiveEventHandler(dual_sock_conn* sockConn){
	int 			fdw_i= -1;
	char 			buffer[_BUFFER_SIZE];
	unsigned int	i, bytesRecv, iPayloadData;

	if (_VERBOSE_MODE) printf("[socket fd:%d]\tnew data from this user socket was received\n", sockConn->fdu);

	checkIfError(
		bytesRecv = recv(sockConn->fdu, buffer, _BUFFER_SIZE, 0),
		"socket: recv",
		"couldn't receive data"
	);

	// if the other side closed the socket
	if (bytesRecv == 0){
		if (_VERBOSE_MODE) printf("[socket fd:%d]\tother side closed the socket\n", sockConn->fdu);

		close(sockConn->fdu);
		if (sockConn->fdw){
			char const* msg = "error('Program Agent was closed by the other side')";
			sockConn->utowBuffer[0] = 0x81;//1000 0001 i.e FIN-bit 0 0 0 Opcode(4 bits)
			sockConn->utowBuffer[1] = (unsigned char)strlen(msg);// Payload Len
			sockConn->utowLen = 2 + sockConn->utowBuffer[1];
			memcpy( sockConn->utowBuffer + 2, msg, sockConn->utowBuffer[1] + 1 );
		}

		sockConn->fdu = sockConn->wtouBuffer[0] = 0;
	}else{
		buffer[bytesRecv] = 0;

		if (_VERBOSE_MODE) printf("[socket fd:%d]\tdata is:\n%s\n", sockConn->fdu, buffer);

		// if what we have received is a web socket message
		if ( !regexec(&regex_wsInitialMsg, buffer, regex_wsInitialMsg.re_nsub+1, matchs, 0) ){
			if (_VERBOSE_MODE) printf("[socket fd:%d]\tWebSocket detected\n", sockConn->fdu);

			for (i=0; i < _MAX_CLIENT; ++i)
				if ( (conns[i].fdu && !conns[i].fdw) && (conns[i].fdu != sockConn->fdu) ){ //a user waiting for a web socket!
					conns[i].fdwHandled_flag = true; //flag to know that this ws is new at this i-th position and its ready-to-read event is already handled

					conns[i].fdw = sockConn->fdu;
					sockConn->fdu = 0;
					sockConn = &conns[i];
					if (_VERBOSE_MODE) printf("[server socket]\tnew dual connection created (ws %d, us %d)\n", sockConn->fdw, sockConn->fdu);
					break;
				}else
				if (fdw_i == -1 && !conns[i].fdw)
					fdw_i = i;

			if (i >= _MAX_CLIENT){//wasn't able to found a free user
				conns[fdw_i].fdwHandled_flag = true; //flag to know that this ws is new at this i-th position and its ready-to-read event is already handled

				conns[fdw_i].fdw = sockConn->fdu;
				sockConn->fdu = 0;
				sockConn = &conns[fdw_i];
				if (_VERBOSE_MODE) printf("[server socket]\tnew WebSocket %d waiting for incoming user sockets\n", sockConn->fdw);
			}

			//WEBSOCKET OPENING HANDSHAKE [RFC 6455 4.2.1-2]
			//1) capturing the Sec-WebSocket-Key value (stores it in fullWebSocketKey)
			if (matchs[2].rm_so == -1)
				memcpy((void *)&matchs[2], (void *)&matchs[3], sizeof(regmatch_t));
			memcpy(fullWebSocketKey, buffer + matchs[2].rm_so, 24);

			//2) concatenating fullWebSocketKey with the GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
			memcpy(fullWebSocketKey + 24, _WS_SPECIFICATION_GUID, 36);

			//3)  taking the SHA-1 hash of this concatenated value to obtain a 20-byte value
			KeyHash = SHA1(fullWebSocketKey, 60);

			//4) and base64-encoding this 20-byte hash
			base64encode(KeyHash , 20, secWebsocketAccept, 29);

			//5) sending the handshake message to the web socket asynchronously
			strcpy(
				handshakeMessage,
				"HTTP/1.1 101 Switching Protocols\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Accept: "
			);
			strcat(handshakeMessage, secWebsocketAccept);
			strcat(handshakeMessage, "\r\n\r\n");

			sockConn->utowLen = strlen(handshakeMessage);
			memcpy( sockConn->utowBuffer, handshakeMessage, sockConn->utowLen + 1 );
		}else{
			//if it is a user socket and doesn't have a ws to exchange data with, try to find a free ws for it
			if (!sockConn->fdw){
				for (i=0; i < _MAX_CLIENT; ++i)
					//if a user socket is waiting for a web socket!
					if ( !conns[i].fdu && conns[i].fdw ){
						conns[i].fduHandled_flag = true;//flag to know that this us is new at this i-th position and its ready-to-read event is already handled

						conns[i].fdu = sockConn->fdu;
						sockConn->fdu = 0;
						sockConn = &conns[i];
						break;
					}
			}
			buffer[bytesRecv] = 0;

			sockConn->utowBuffer[0] = 0x81;//1000 0001 i.e FIN-bit 0 0 0 Opcode(4 bits)
			iPayloadData = 2;

			//[extended] Payload len
			if (bytesRecv <= 125)
				sockConn->utowBuffer[1] = (unsigned char)bytesRecv; // & 0x07F; //& 0111 1111 (MASK bit set to 0);
			else{
				sockConn->utowBuffer[1] = 126;
				*(uint16_t *)&sockConn->utowBuffer[2] = htons( (uint16_t)bytesRecv );
				iPayloadData+=2; //2 bytes = 16 bits
			}

			sockConn->utowLen = iPayloadData + bytesRecv;
			//sending data to the websocket asynchronously encapsulated in a websocket frame
			if (sockConn->fdw)
				memcpy(sockConn->utowBuffer + iPayloadData, buffer, bytesRecv + 1);
			else
				if (_VERBOSE_MODE) printf("[socket fd:%d]\tno webSocket to send data to\n", sockConn->fdu);
		}
	}
}

void onWStoUSSendEventHandler(dual_sock_conn* sockConn){
	if (sockConn->wtouBuffer[0]){
		if (_VERBOSE_MODE) printf("[socket fd:%d]\tsends data to the user socket[%d]:\n%s\n", sockConn->fdw, sockConn->fdu, sockConn->wtouBuffer);
		write(sockConn->fdu, sockConn->wtouBuffer, strlen(sockConn->wtouBuffer));//send
		*(int *)sockConn->wtouBuffer = 0;
	}
}

void onUStoWSSendEventHandler(dual_sock_conn* sockConn){
	if (sockConn->utowBuffer[0]){
		if (_VERBOSE_MODE) printf("[socket fd:%d]\tsends data to the WebSocket[%d]:\n%s\n", sockConn->fdu, sockConn->fdw, sockConn->utowBuffer);
		write(sockConn->fdw, sockConn->utowBuffer, sockConn->utowLen);//send
		sockConn->utowBuffer[0] = 0;
	}
}

int main(int argc, char const* argv[]){
	int i;

	//redirectiong standard error (stderr) to standard output (stdout)
	dup2(STDOUT_FILENO, STDERR_FILENO);

	//handles the input arguments
	for (i=1; i < argc; ++i){
		if (!strcmp(argv[i], "--port") || !strcmp(argv[i], "-p")){
			//if port number is not valid (or empty)
			if (i+1 >= argc || atoi(argv[i+1]) < 1){
				perror("error: the port number must be between 1 and 65535\n");
				exit(EXIT_FAILURE);
			}
			_PORT = atoi(argv[++i]);
		}else
		if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v"))
			_VERBOSE_MODE = true;
		else
		if (!strcmp(argv[i], "--no-forwarding") || !strcmp(argv[i], "-n"))
			_WS_TO_US_FORWARDING = false;
		else
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-?"))
			displayHelp(argv[0]);
		else{
			//fprintf(stderr, "%s: invalid option '%s'\n\n", argv[0], argv[i]);
			printf("%s: invalid option '%s'\n\n", argv[0], argv[i]);
			displayHelp(argv[0]);
		}
	}

	//prints program header
	printf(
		"Tileworld Proxy (version 1.0)\n"
		"Copyright (c) 2014 Sergio Burdisso\n\n"
	);

	if (!_PORT){
		printf("No port number was provided (using the default value %d)\n\n", _DEFAULT_PORT);
		_PORT = _DEFAULT_PORT;
	}

	//compiles the regular expression used to parse the websocket opening handshake message
	regcomp(
		&regex_wsInitialMsg,
		"GET[ \t].*"
		"(\r\nUpgrade[ \t]*:[ \t]*websocket.*\r\nSec-WebSocket-Key[ \t]*:[ \t]*([^\r\t ]*)|"
		"\r\nSec-WebSocket-Key[ \t]*:[ \t]*([^\r\t ]*).*\nUpgrade[ \t]*:[ \t]*websocket).*",
		REG_ICASE | REG_EXTENDED
	);

	//creates the server socket (i.e the listen()-er socket)
	fdServerSock =socket(
					AF_INET 	/*Internet domain sockets (IPv4)*/,
					SOCK_STREAM	/*Byte-stream socket*/,
					IPPROTO_TCP	/*actual transport protocol to be used (TCP)*/
				);

	checkIfError(fdServerSock, "socket", "somehow the Operating System is denying the creation of sockets for this process");
	setNonBlockingFlag(fdServerSock);

	//initializing variables to have 0 values (avoiding garbage values)
	memset((void *)&serverAddress	, 0, sizeof(serverAddress	));
	memset((void *)conns			, 0, sizeof(conns			));

	//filling up the serverAddress fields (i.e setting up our server address)
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);	//host byte order INADDR_ANY to equivalent network byte order long
	serverAddress.sin_port = htons(_PORT); 				//host byte order _PORT to equivalent network byte order short


	checkIfError(
		//binding our listener socket to the given address:port
		bind(fdServerSock, (const struct sockaddr*)&serverAddress, sizeof(serverAddress)),
		"socket: bind",
		"(address, port) not allowed.\n"
		"    try the following solutions in the order that they're listed:\n\n"
		"        -Find and close the process that is already using this port numbr\n\n"
		"        -Your Operating System  may be  reserving Port numbers  less than\n"
		"         256 for well-known services (like HTTP on port 80) and port num-\n"
		"         bers less  than 1024 require root  access on UNIX-based systems.\n"
		"         Either try switching to root user or using a Port number greater\n"
		"         then or equal to 1024\n\n"
		"        -If you have  recently  closed  another instance  of this program,\n"
		"         your Operating  System could've put  the socket  into a TIME_WAIT\n"
		"         state before finally closing it,  so wait a few  minutes  and try\n"
		"         again" 
	);

	checkIfError(
		//prepares listener socket for incoming connections
		//sets the number of pending connections that can be queued up to _QUEUE_LENGTH_
		listen(fdServerSock, _QUEUE_LENGTH_),
		"sock: listen",
		"couldn't prepare the server for incoming connections"
	);

	printf("Tileworld proxy running on port %d\n", _PORT);

	fdMax = fdServerSock;

	//server main loop
	for(/*infinite*/;/*loop*/;/*it!*/){

		//1) Initializes the file descriptor sets
		resetAndSetFileDescriptorSets();

		//3) blocks the process waiting for I/O events to happen
		checkIfError(
			fdsReady = select(fdMax + 1, (fd_set *)&fdReadSocks, (fd_set *)&fdWriteSocks, NULL, NULL/*timeout*/),
			"system: select",
			"while trying to wait for sockets I/O events to happen"
		);

		//handling new connection (if necessary)
		if (FD_ISSET(fdServerSock, &fdReadSocks))
			newConnectionEventHandler();

		//handling current connections
		for (i=0; i < _MAX_CLIENT; ++i){
			//ready-for-receiving events handler
			if ( !conns[i].fdwHandled_flag && FD_ISSET(conns[i].fdw, &fdReadSocks) )
				onWSReceiveEventHandler(&conns[i]);

			if ( !conns[i].fduHandled_flag && FD_ISSET(conns[i].fdu, &fdReadSocks) )
				onUSReceiveEventHandler(&conns[i]);

			//ready-for-sending events handler
			if ( FD_ISSET(conns[i].fdw, &fdWriteSocks) )
				onUStoWSSendEventHandler(&conns[i]);

			if ( FD_ISSET(conns[i].fdu, &fdWriteSocks) )
				onWStoUSSendEventHandler(&conns[i]);

		}//for
	}//infinite loop

	close(fdServerSock);
	regfree(&regex_wsInitialMsg);

	return 0;
}//main
