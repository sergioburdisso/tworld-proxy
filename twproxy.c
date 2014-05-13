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

#define _PORT_					8000
#define _MAX_CLIENT				32
#define _BUFFER_SIZE			16*1024//16KB
#define _QUEUE_LENGTH_			16
#define _WS_SPECIFICATION_GUID	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef enum _bool {false=0, true=1} bool;
typedef struct sockaddr_in sockaddr_in;

// (1:1 mapping)
// NOTE: fd stands for File Descriptor which is essentially an index for a kernel-resident array data structure
// associated with this process used to keep track of all the buffer-based resources that the process is working with
typedef struct _dual_sock_conn{
	int			fdw;			// file descriptor assigned to the web socket
	int			fdu;			// file descriptor assigned to the user socket
	bool		newfdw_flag;	// flag used to indicate if the fdw correspond to a new webSocket (fdw)
	char*		wtouBuffer; 	// buffer used to send data from WebSocket to user socket
	char*		utowBuffer;		// buffer used to send data from user socket to WebSocket
	uint16_t	utowLen;		// number of bytes to be send from WebSocket to user socket
} dual_sock_conn;

//SELECT
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

//is it an error?
void checkIfError(int value, char const* origin, char const* msg){
	if (value < 0){
		fprintf (stderr, "%s: error:\n\t%s\n\n", origin, (msg!=NULL)? msg: "an unknown error has occurred");
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
			conns[i].newfdw_flag = false;

			FD_SET(conns[i].fdw, &fdReadSocks );
			FD_SET(conns[i].fdw, &fdWriteSocks);
		}

		if ( conns[i].fdu ){
			FD_SET(conns[i].fdu, &fdReadSocks );
			FD_SET(conns[i].fdu, &fdWriteSocks);
		}
	}
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

			printf("[server socket]\tnew connection accepted [new socket fd:%d]\n", fdConnect); // TODO: --> luego agregar todos los mensajes /verbose o no
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

	printf("[socket fd:%d]\tWebSocket receives data\n", sockConn->fdw);

	checkIfError(
		bytesRecv = recv(sockConn->fdw, buffer, _BUFFER_SIZE, 0),
		"socket: recv",
		"couldn't receive data"
	);

	// if the other side closed the socket
	if (bytesRecv == 0){
		printf("[socket fd:%d]\tother side closed the socket\n", sockConn->fdw);

		close(sockConn->fdw);

		if (sockConn->fdu){
			char const* msg = "_ERROR_: Tileworld instance was closed by other side";
			memcpy( sockConn->wtouBuffer, msg, strlen(msg)+1 );
		}

		sockConn->fdw = sockConn->utowBuffer[0] = 0;
	}else{
		buffer[bytesRecv] = 0;

		printf("[socket fd:%d]\tdata received is:\n%s\n", sockConn->fdw, buffer);

		//if ws socket doesnt have a user to exchange data with, try to find a free user for it
		if (!sockConn->fdu){
			for (i=0; i < _MAX_CLIENT; ++i)
				if ( !conns[i].fdw && conns[i].fdu ){ //if a user is waiting for a web socket!
					conns[i].fdw = sockConn->fdw;
					sockConn->fdw = 0;
					sockConn = &conns[i];
					break;
				}
		}

		//WebSocket Message (see section 5 "Data Framing" from the RFC 6455) 
		/*printf(
			"\n\nraw websocket message:\n------------------------\n|%d|%d|%d|%d|x%x\t|%d|x%x\t|\n",
			(buffer[0]&0x80)? 1 : 0,	// FIN bit
			(buffer[0]&0x40)? 1 : 0,	// RSV1 bit
			(buffer[0]&0x20)? 1 : 0,	// RSV2 bit
			(buffer[0]&0x10)? 1 : 0,	// RSV3 bit
			buffer[0]&0x01,				// opcode (4 bits)

			(buffer[1]&0x80)? 1 : 0,	// MASK bit
			buffer[1]&0x7F				// Payload len (7 bits)
		);*/

		//opcode != 1
		/*if (buffer[0]&0x80 != 1)
			agregar al buffer y esperar hasta que sea 1
		else
			enviar el buffer*/

		/*if (buffer[0]&0x01 != 1)
			enviar(close frame con codigo 1003 7.4.1.  Defined Status Codes)*/

		/*if (buffer[1]&0x80 == 0)// MASK bit) no se admiten mensajes sin mascara
			enviar(close frame con codigo VER CODIGO 7.4.1.  Defined Status Codes)*/

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

		//unmasking the receive payload data [RFC 6455 5.3]
		for (i=0; i < payloadLength; ++i)
			buffer[iPayloadData+i] = buffer[iPayloadData+i] ^ buffer[iMaskingKey + i%4];

		buffer[iPayloadData + payloadLength] = 0;

		//sending data to the web socket asynchronously
		if (sockConn->fdu)
			memcpy(sockConn->wtouBuffer, buffer + iPayloadData, payloadLength+1);
		else
			printf("[socket fd:%d]\tno user socket to send\n", sockConn->fdw);
	}
}

void onUSReceiveEventHandler(dual_sock_conn* sockConn){
	int 			fdw_i= -1;
	char 			buffer[_BUFFER_SIZE];
	unsigned int	i, bytesRecv, iPayloadData;

	printf("[socket fd:%d]\tuser socket receives data\n", sockConn->fdu);

	checkIfError(
		bytesRecv = recv(sockConn->fdu, buffer, _BUFFER_SIZE, 0),
		"socket: recv",
		"couldn't receive data"
	);

	// if the other side closed the socket
	if (bytesRecv == 0){
		printf("[socket fd:%d]\tother side closed the socket\n", sockConn->fdu);

		close(sockConn->fdu);
		if (sockConn->fdw){
			char const* msg = "_ERROR_: Program Agent was closed by other side";
			sockConn->utowBuffer[0] = 0x81;//1000 0001 i.e FIN-bit 0 0 0 Opcode(4 bits)
			sockConn->utowBuffer[1] = (unsigned char)strlen(msg);// Payload Len
			sockConn->utowLen = 2 + sockConn->utowBuffer[1];
			memcpy( sockConn->utowBuffer + 2, msg, sockConn->utowBuffer[1] + 1 );
		}

		sockConn->fdu = sockConn->wtouBuffer[0] = 0;
	}else{
		buffer[bytesRecv] = 0;

		printf("[socket fd:%d]\tdata received is:\n%s\n", sockConn->fdu, buffer);

		// if what we have received is a web socket message
		if ( !regexec(&regex_wsInitialMsg, buffer, regex_wsInitialMsg.re_nsub+1, matchs, 0) ){
			printf("[socket fd:%d]\tWebSocket detected\n", sockConn->fdu);

			for (i=0; i < _MAX_CLIENT; ++i)
				if ( (conns[i].fdu && !conns[i].fdw) && (conns[i].fdu != sockConn->fdu) ){ //a user waiting for a web socket!
					conns[i].newfdw_flag = true; //flag to know that this is a new ws and it's ready-to-read event was already served here

					conns[i].fdw = sockConn->fdu;
					sockConn->fdu = 0;
					sockConn = &conns[i];
					printf("[server socket]\tnew dual connection (ws %d, us %d)\n", sockConn->fdw, sockConn->fdu);
					break;
				}else
				if (fdw_i == -1 && !conns[i].fdw)
					fdw_i = i;

			if (i >= _MAX_CLIENT){//wasn't able to found a free user
				conns[fdw_i].newfdw_flag = true; //flag to know that this is a new ws and it's ready-to-read event was already served here

				conns[fdw_i].fdw = sockConn->fdu;
				sockConn->fdu = 0;
				sockConn = &conns[fdw_i];
				printf("[server socket]\tnew WebSocket %d waiting for incoming user sockets\n", sockConn->fdw);
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
			//if is not ws and user socket doesnt have a ws to exchange data with, try to find a free ws for it
			if (!sockConn->fdw){
				for (i=0; i < _MAX_CLIENT; ++i)
					if ( !conns[i].fdu && conns[i].fdw ){ //a user waiting for a web socket!
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
				printf("[socket fd:%d]\tno webSocket to send\n", sockConn->fdu);
		}
	}
}

void onWStoUSSendEventHandler(dual_sock_conn* sockConn){
	if (sockConn->wtouBuffer[0]){
		printf("[socket fd:%d]\tsend data to the user socket[%d]:\n%s\n", sockConn->fdw, sockConn->fdu, sockConn->wtouBuffer);
		write(sockConn->fdu, sockConn->wtouBuffer, strlen(sockConn->wtouBuffer)+1);//send
		sockConn->wtouBuffer[0] = 0;
	}
}

void onUStoWSSendEventHandler(dual_sock_conn* sockConn){
	if (sockConn->utowBuffer[0]){
		printf("[socket fd:%d]\tsend data to the WebSocket[%d]:\n%s\n", sockConn->fdu, sockConn->fdw, sockConn->utowBuffer);
		write(sockConn->fdw, sockConn->utowBuffer, sockConn->utowLen);//send
		sockConn->utowBuffer[0] = 0;
	}
}

int main(int argc, char const* argv[]){
	printf("\nTileworld WebSocket proxy server running at port %d\nSergio Burdisso - 2014\n\n", _PORT_);

	regcomp(
		&regex_wsInitialMsg,
		"GET[ \t].*"
		"(\r\nUpgrade[ \t]*:[ \t]*websocket.*\r\nSec-WebSocket-Key[ \t]*:[ \t]*([^\r\t ]*)|"
		"\r\nSec-WebSocket-Key[ \t]*:[ \t]*([^\r\t ]*).*\nUpgrade[ \t]*:[ \t]*websocket).*",
		REG_ICASE | REG_EXTENDED
	);

	fdServerSock =socket(
					AF_INET 	/*Internet domain sockets (IPv4)*/,
					SOCK_STREAM	/*Byte-stream socket*/,
					IPPROTO_TCP	/*actual transport protocol to be used (TCP)*/
				);

	checkIfError(fdServerSock, "socket", "somehow the Operating System is denying the creation of sockets to this process");
	setNonBlockingFlag(fdServerSock);

	//initializing variables to have 0 values (avoiding garbage values)
	memset((void *)&serverAddress	, 0, sizeof(serverAddress	));
	memset((void *)conns			, 0, sizeof(conns			));

	//filling up the serverAddress fields (i.e setting up our server address)
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);	//host byte order INADDR_ANY to equivalent network byte order long
	serverAddress.sin_port = htons(_PORT_); 			//host byte order _PORT_ to equivalent network byte order short


	checkIfError(
		//binding the our listener socket to the given address
		bind(fdServerSock, (const struct sockaddr*)&serverAddress, sizeof(serverAddress)),
		"socket: bind",
		"address already in use (try closing the process is already using this address)"
	);

	checkIfError(
		//prepares listener socket for incoming connections
		//sets the number of pending connections that can be queued up to _QUEUE_LENGTH_
		listen(fdServerSock, _QUEUE_LENGTH_),
		"sock: listen",
		"couldn't prepare the server for incoming connections"
	);

	fdMax = fdServerSock;

	for(/*infinite*/;/*loop*/;/*it!*/){
		int i;

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

		//handling connections
		for (i=0; i < _MAX_CLIENT; ++i){
			//ready for receiving event handler
			if ( !conns[i].newfdw_flag && FD_ISSET(conns[i].fdw, &fdReadSocks) )
				onWSReceiveEventHandler(&conns[i]);


			if ( FD_ISSET(conns[i].fdu, &fdReadSocks) )
				onUSReceiveEventHandler(&conns[i]);

			//ready for sending events
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
