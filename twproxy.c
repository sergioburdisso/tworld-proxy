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

#define _PORT_			8000
#define _QUEUE_LENGTH_	16
#define _MAX_CLIENT		32
#define _BUFFER_SIZE	4*1024//4KB

typedef enum _bool {false=0, true=1} bool;
typedef struct sockaddr_in sockaddr_in;

// (1:1 mapping)
// NOTE: fd stands for File Descriptor which is essentially an index for a kernel-resident array data structure
// associated with this process used to keep track of all the buffer-based resources that the process is working with
typedef struct _dual_sock_conn{
	int		fdw;			// file descriptor assigned to the web socket
	int		fdu;			// file descriptor assigned to the user socket
	char*	wtouBuffer; 	// buffer used to send data from WebSocket to user socket
	char*	utowBuffer;		// buffer used to send data from user socket to WebSocket
	bool	newfdw_flag;	// flag used to indicate if the fdw correspond to a new webSocket (fdw)
} dual_sock_conn;

int fdMax;							// used in select (stores the biggest file descriptor assigned to this process so far)
int fdsReady;						// used in select (number of fds that have changed)
fd_set fdReadSocks, fdWriteSocks;	// used in select (set of fds we are going to wait for events to happen --write/read)
sockaddr_in serverAddress;			// address the listener socket is going to be binded to
dual_sock_conn conns[_MAX_CLIENT];	// array of paired connections (webSocket, userSocket) needed for the 1 to 1 map
int fdServerSock;					// fd for the server socket (i.e the listen()-er socket)

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

	//2) adding the fds of the sockets we want to be woken up by (whenever I/O events happen) to he fd sets
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
	int i, bytesRecv;
	char buffer[_BUFFER_SIZE];

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
			char const* msg = "_ERROR: Tileworld instance was closed by other side";
			memcpy( sockConn->wtouBuffer, msg, strlen(msg)+1 );
		}

		sockConn->fdw = sockConn->utowBuffer[0] = 0;
	}else{
		buffer[bytesRecv] = 0;

		printf("[socket fd:%d]\tdata received is:\n%s\n", sockConn->fdw, buffer);

		if (!sockConn->fdu){//if ws socket doesnt have a user to exchange data with, try to find a free user for it
			for (i=0; i < _MAX_CLIENT; ++i)
				if ( !conns[i].fdw && conns[i].fdu ){ //a user waiting for a web socket!
					conns[i].fdw = sockConn->fdw;
					sockConn->fdw = 0;
					sockConn = &conns[i];
					break;
				}
		}

		//sending data to the web socket asynchronously
		if (sockConn->fdu)
			memcpy(sockConn->wtouBuffer, buffer/*<- build ws protocol packet with this data in it*/, bytesRecv + 1);
		else
			printf("[socket fd:%d]\tno user socket to send\n", sockConn->fdw);
	}
}

void onUSReceiveEventHandler(dual_sock_conn* sockConn){
	int i, fdw_i= -1, bytesRecv;
	char buffer[_BUFFER_SIZE];

	printf("[socket fd:%d]\tuser socket receives data\n", sockConn->fdu);

	checkIfError(
		bytesRecv = recv(sockConn->fdu, buffer, _BUFFER_SIZE, 0),
		"socket: recv",
		"couldn't receive data"
	);

	if (bytesRecv == 0){
		/* This means the other side closed the socket */
		printf("[socket fd:%d]\tother side closed the socket\n", sockConn->fdu);

		close(sockConn->fdu);
		if (sockConn->fdw){
			char const* msg = "_ERROR: Program Agent was closed by other side";
			memcpy( sockConn->utowBuffer, msg, strlen(msg)+1 );
			//close(sockConn->fdw);
		}

		sockConn->fdu = sockConn->wtouBuffer[0] = 0;
	}else{
		buffer[bytesRecv] = 0;

		printf("[socket fd:%d]\tdata received is:\n%s\n", sockConn->fdu, buffer);

		// if what we have received is a web socket message
		if ( strstr(buffer, "Upgrade: websocket") ){
			char const* msg;

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

			//sending data to the web socket asynchronously
			//WebSocket handshake!
			msg= "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: YzNlODAwMGU1NWRjYzg5NmNjZmNlZGIzZWNkNzViMWUyMmFhMjIyYQ==\r\n\r\n";
			memcpy( sockConn->utowBuffer, msg, strlen(msg)+1 );

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

			//sending data to the web socket asynchronously
			if (sockConn->fdw)
				memcpy(sockConn->utowBuffer, buffer/*<- build ws protocol packet with this data in it*/, bytesRecv + 1);
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
		write(sockConn->fdw, sockConn->utowBuffer, strlen(sockConn->utowBuffer)+1);//send
		sockConn->utowBuffer[0] = 0;
	}
}

int main(int argc, char const* argv[]){
	printf("Tileworld WebSocket proxy server running at port %d\nSergio Burdisso - 2014\n\n", _PORT_);

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

	return 0;
}//main
