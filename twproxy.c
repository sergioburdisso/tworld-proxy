/*
* twproxy.c
*
* Copyright (C) 2014 Burdisso Sergio (sergio.burdisso@gmail.com)
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//
// HEADERS
//
#include <netinet/in.h>
#include <netinet/tcp.h>
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


//
// PREPROCESSOR-TIME CONSTANTS
//
#define _FD_MASK                0x7FFF
#define _MAX_CLIENT             128
#define _BUFFER_SIZE            16*1024//16KB
#define _DEFAULT_PORT           3313
#define _QUEUE_LENGTH_          16
#define _FD_HANDLED_FLAG        0x8000
#define _CONNECT_MESSAGE        "CONNECT:"
#define _XML_XSD_LOCATION       "./resrc/tw_msg.xsd"
#define _WS_CLOSED_MESSAGE      "T-World instance was closed by the other side"
#define _WS_CONNECT_MESSAGE     "_CONNECTED_"
#define _WS_DISCONNECT_MESSAGE  "_DISCONNECTED_"
#define _WS_SPECIFICATION_GUID  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


//
// DATA TYPES DEFINITIONS
//
typedef struct sockaddr_in sockaddr_in;
typedef enum _bool {false=0, true=1} bool;
typedef enum _format {JSON='{', XML='<', PROLOG=' ', UNKNOWN='\0'} data_format;

//NOTE: fd stands for File Descriptor which is basically an index for a kernel-resident array data structure
//      associated with this process used to keep track of all the buffer-based resources that the process is working with

//struct used to keep track of each (1:1) connection
typedef struct _dual_sock_conn{
    char        magic_string[128];// string that is used to link the agent program algorithm (raw socket) to the right t-world agent program

    uint16_t    fdw;              // file descriptor assigned to the web socket (HANDLED bit + FD (15 bits))
    char*       rtowBuffer;       // buffer used to send data from the raw socket to the WebSocket
    char*       towBuffer;        // buffer used to send data (constant strings) from the server to the WebSocket
    uint16_t    rtowLen;          // number of bytes to be send from raw socket to WebSocket

    uint16_t    fdr;              // file descriptor assigned to the raw socket (HANDLED bit + FD (15 bits))
    char*       wtorBuffer;       // buffer used to send data from the WebSocket to the raw socket
    data_format wtorFormat;       // format of data sent to the raw socket (JSON, XML, PROLOG)
} dual_sock_conn;


//
// VARIABLE DEFINITIONS
//
//for select() system call
int     fdMax;                      // stores the biggest file descriptor assigned to this process so far
int     fdsReady;                   // number of fds that have changed
fd_set  fdReadSocks, fdWriteSocks;  // set of fds we are going to wait for events to happen --write/read

//Server socket
int         fdServerSock;           // fd for the server socket (i.e the listen()-er socket)
sockaddr_in serverAddress;          // address the listen()-er socket is going to be binded to

//Connections
dual_sock_conn conns[_MAX_CLIENT];  // array of paired connections (webSocket, userSocket) needed for the 1 to 1 map

//WebSocket protocol handshake [RFC 6455]
regmatch_t matchs[4];               // stores the substrings matching the subpatterns (within regex_wsInitialMsg)
unsigned char* KeyHash;             // Stores the SHA1(fullWebSocketKey) 160 bits value for the server handshake replay
char fullWebSocketKey[60];          // Sec-WebSocket-Key base64-encoded value (when decoded, is 16 bytes in length)
char handshakeMessage[1024];         // Stores the full handshake message to be sent to the WebSocket
char secWebsocketAccept[29];        // Stores the Base64(SHA-1(fullWebSocketKey))
regex_t regex_wsInitialMsg;         // compiled regular expression for detecting websocket handshake from web browser

//program input options
uint16_t    _PORT = 0;
bool        _VERBOSE_MODE = false;
bool        _WS_TO_RS_FORWARDING = true;


//
// FUNCTION DECLARATIONS (PROTOTYPES)
//
void resetAndSetFileDescriptorSets  (void);                         // Initializes the file descriptor sets (used for select()-ing the sockets we take care of)
void newConnectionEventHandler      (void);                         // handles new connection
void onWStoRSSendEventHandler       (dual_sock_conn*);              // ready-to-send (to raw socket) event handler
void onRStoWSSendEventHandler       (dual_sock_conn*);              // ready-to-send (to WebSocket) event handler
void onWSReceiveEventHandler        (dual_sock_conn*);              // ready-to-receive (from WebSocket) event handler
void onRSReceiveEventHandler        (dual_sock_conn*);              // ready-to-receive (from raw socket) event handler
char* getConnectMagicString         (char*);                        // returns the Magic String in case of a CONNECT message, NULL otherwise
void setNonBlockingFlag             (int);                          // tells the kernel the socket linked to a fd is nonblocking
void sendToWS                       (dual_sock_conn*, char const*); // sends a constant websocket message to a certain WebSocket
void closeWS                        (dual_sock_conn*);              // sends a close frame to a certain WebSocket

void exit_twproxy                   (int);                          // proxy terminates its execution
void checkIfError                   (int,char const*,char const*,bool);// checks if first argument is a negative number, prints an error and terminates execution
void displayHelp                    (char const*);                  // prints the help dialog
char toLowerCase                    (char);                         //convert a character from upper case to lower case
bool istrcmp                        (const char*, const char*);     //case insensitive string comparison (e.g. used for detecting the magic string) 


//
// FUNCTION DEFINITIONS
//
int main (int argc, char const* argv[]) {
    uint16_t i, ifdr, ifdw;

    //redirecting standard error (stderr) to standard output (stdout)
    dup2(STDOUT_FILENO, STDERR_FILENO);

    //handles the input options
    for (i=1; i < argc; ++i){
        if (istrcmp(argv[i], "--port") || istrcmp(argv[i], "-p")){
            //if port number is not valid (or empty)
            if (i+1 >= argc || atoi(argv[i+1]) < 1){
                perror("error: the port number must be between 1 and 65535\n");
                exit(EXIT_FAILURE);
            }
            _PORT = atoi(argv[++i]);
        }else
        if (istrcmp(argv[i], "--verbose") || istrcmp(argv[i], "-v"))
            _VERBOSE_MODE = true;
        else
        if (istrcmp(argv[i], "--no-forwarding") || istrcmp(argv[i], "-n"))
            _WS_TO_RS_FORWARDING = false;
        else
        if (istrcmp(argv[i], "--help") || istrcmp(argv[i], "-?"))
            displayHelp(argv[0]);
        else{
            //fprintf(stderr, "%s: invalid option '%s'\n\n", argv[0], argv[i]);
            printf("%s: invalid option '%s'\n\n", argv[0], argv[i]);
            displayHelp(argv[0]);
        }
    }

    //prints program header
    printf(
        "T-World Proxy (version 1.0)\n"
        "Copyright (c) 2014 Burdisso Sergio\n"
        "T-World Proxy comes with ABSOLUTELY NO WARRANTY. This is free software,\n"
        "and you are welcome to redistribute it under certain conditions.\n"
        "Please visit http://www.gnu.org/licenses/gpl-3.0.html for details.\n\n"
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
                    AF_INET     /*Internet domain sockets (IPv4)*/,
                    SOCK_STREAM /*Byte-stream socket*/,
                    IPPROTO_TCP /*actual transport protocol to be used (TCP)*/
                );

    checkIfError(fdServerSock, "socket", "somehow the Operating System is denying the creation of sockets for this process", true);
    setNonBlockingFlag(fdServerSock);

    //initializing variables to have 0 values (avoiding garbage values)
    memset((void *)&serverAddress   , 0, sizeof(serverAddress   ));
    memset((void *)conns            , 0, sizeof(conns           ));

    //filling up the serverAddress fields (i.e setting up our server address)
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);  //host byte order INADDR_ANY to equivalent network byte order long
    serverAddress.sin_port = htons(_PORT);              //host byte order _PORT to equivalent network byte order short


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
        "         again",
        true
    );

    checkIfError(
        //prepares listener socket for incoming connections
        //sets the number of pending connections that can be queued up to _QUEUE_LENGTH_
        listen(fdServerSock, _QUEUE_LENGTH_),
        "sock: listen",
        "couldn't prepare the server for incoming connections",
        true
    );

    printf("T-World proxy running on port %d\n\n", _PORT);

    fdMax = fdServerSock;

    // server main loop
    for(/*infinite*/;/*loop*/;/*it!*/){

        //1) Initializes the file descriptor sets
        resetAndSetFileDescriptorSets();

        //3) blocks the process waiting for I/O events to happen
        checkIfError(
            fdsReady = select(fdMax + 1, (fd_set *)&fdReadSocks, (fd_set *)&fdWriteSocks, NULL, NULL/*timeout*/),
            "system: select",
            "while trying to wait for sockets I/O events to happen",
            true
        );

        //4) handles new connection (if necessary)
        if (FD_ISSET(fdServerSock, &fdReadSocks))
            newConnectionEventHandler();

        //5) handles current connections
        for (i=0; i < _MAX_CLIENT; ++i){
            //Note: the first bit of conns[i].fdw/r is a flag used to indicate whether
            //      the fdw/r is new at conns[i] (and thus its events were previously handled)

            //-> ready-to-receive event handlers
            if ( !(conns[i].fdw&_FD_HANDLED_FLAG) && FD_ISSET(conns[i].fdw, &fdReadSocks) )
                onWSReceiveEventHandler(&conns[i]);

            if ( !(conns[i].fdr&_FD_HANDLED_FLAG) && FD_ISSET(conns[i].fdr, &fdReadSocks) )
                onRSReceiveEventHandler(&conns[i]);

            //-> ready-to-send event handlers
            if ( FD_ISSET(conns[i].fdw&_FD_MASK, &fdWriteSocks) )
                onRStoWSSendEventHandler(&conns[i]);

            if ( FD_ISSET(conns[i].fdr&_FD_MASK, &fdWriteSocks) )
                onWStoRSSendEventHandler(&conns[i]);
        }// for
    }// infinite loop

    exit_twproxy(EXIT_SUCCESS);

    return 0;
}//main

// T-World proxy terminates its execution
void exit_twproxy (int status) {
    close(fdServerSock);
    regfree(&regex_wsInitialMsg);

    exit(status);
}

// prints the help dialog
void displayHelp (char const* programName) {
    printf(
        "Usage: %s [OPTION]...\n\n"
        "OPTIONS:\n\n"
        "-p, --port <NUM>       Allow you to define the port number your T-World Proxy\n"
        "                       will listen on.  The port  number must be  between 1 and\n"
        "                       65535.  If no value is provided, this property is set to\n"
        "                       the default value of %d\n\n"
        "-v, --verbose          Allow the application to display trace information\n\n"
        "-n, --no-forwarding    Disable forwarding data coming from  the 3D T-World to\n"
        "                       the user program\n\n"
        "-?, --help             Display this help and exit\n\n",
        programName, _DEFAULT_PORT
    );
    exit(EXIT_SUCCESS);
}

// checks if first argument is a negative number, prints an error and terminates execution (if necessary)
void checkIfError (int value, char const* origin, char const* msg, bool fatal) {
    if (value < 0){

        if (fatal || _VERBOSE_MODE)
            //fprintf (stderr, "%s: error:\n\t%s\n\n", origin, (msg!=NULL)? msg: "an unknown error has occurred"); <- not working on my Android device :(
            printf("%s: error: %s.\n\n", origin, (msg!=NULL)? msg: "an unknown error has occurred");

        if (fatal)
            exit_twproxy(EXIT_FAILURE);
    }
}

//convert a character from upper case to lower case
char toLowerCase(char c){ return (('A' <= c && c <= 'Z')? c + ('a' - 'A') : c);}

//case insensitive string comparison (e.g. used for detecting the magic string) 
bool istrcmp(const char* str0, const char* str1){
    int len = strlen(str0);
    int _UpperCase = 'A' - 'a';

    if (len != strlen(str1))
        return false;

    while (len--)
        if ( toLowerCase(str0[len]) != toLowerCase(str1[len]) )
            return false;

    return true;
}

// "tells the Kernel that this process does not need to wait for (block until) this socket to complete reading/writing"
void setNonBlockingFlag (int fdSock) {
    int flags;

    setsockopt(fdSock, IPPROTO_TCP, TCP_NODELAY, (char *) &flags, sizeof(int));

    //getting the flags associated with the socket
    //from the Kernel's File Descriptors array assigned to this process
    //using fdSock as index
    //flags = fcntl(fdSock,F_GETFL);
    if (flags < 0) {
        perror("fcntl: error: cant get the socket flags (F_GETFL) from the kernel-resident file descriptors array related to this process");
        exit_twproxy(EXIT_FAILURE);
    }

    //setting the O_NONBLOCK bit to one
    flags = (flags | O_NONBLOCK);
    if (fcntl(fdSock,F_SETFL,flags) < 0) {
        perror("fcntl: error: cant set the socket flags (F_SETFL) in the kernel-resident file descriptors array related to this process");
        exit_twproxy(EXIT_FAILURE);
    }

}

// Initializes the file descriptor sets (used for select()-ing the sockets we take care of)
void resetAndSetFileDescriptorSets () {
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
            conns[i].fdr &= _FD_MASK; // fdr handled = false (flag bit = 0);
            conns[i].fdw &= _FD_MASK; // fdw Handled = false (flag bit = 0);

            FD_SET(conns[i].fdw, &fdReadSocks );
            FD_SET(conns[i].fdw, &fdWriteSocks);
        }

        if ( conns[i].fdr ){
            FD_SET(conns[i].fdr, &fdReadSocks );
            FD_SET(conns[i].fdr, &fdWriteSocks);
        }
    }
}

// returns the Magic String in case of a CONNECT message, NULL otherwise
char* getConnectMagicString(char* msg){
    int i, msg_len = strlen(msg);
    int connect_len = strlen(_CONNECT_MESSAGE);
    const char* CONNECT = _CONNECT_MESSAGE;

    for (i= 0; i < msg_len && i < connect_len; ++i)
        if ( toLowerCase(msg[i]) != toLowerCase(CONNECT[i]) )
            return NULL;

    if (i < connect_len)
        return NULL;
    else{
        //trimming the magic string
        for (i= msg_len; i-- && (msg[i] == '\n' || msg[i] == '\r' || msg[i] == ' ');)
            msg[i] = '\0';
        return msg + connect_len;
    }
}

// handles new connection
void newConnectionEventHandler () {
    int i, fdConnect;

    checkIfError(
        fdConnect = accept(fdServerSock, NULL/*client address (not necessary)*/, NULL),
        "socket: connect",
        "couldn't create the socket for a new connection",
        false
    );
    // if there was an error
    if (fdConnect < 0) return;

    if (fdConnect > fdMax)
        fdMax = fdConnect;

    // assumes that it is not a webSocket and adds it to the conns list
    // (this will change later on in case the data received from this socket
    // corresponds to that of the WebSocket Protocol (i.e. the WebSocket handshake))
    for (i=0; i < _MAX_CLIENT; ++i){
        if ( !conns[i].fdw && !conns[i].fdr ){

            conns[i].fdr = fdConnect;
            //creating buffer on demand
            if (conns[i].wtorBuffer == NULL){
                conns[i].wtorBuffer = (char *)calloc(sizeof(char), _BUFFER_SIZE);
                conns[i].rtowBuffer = (char *)calloc(sizeof(char), _BUFFER_SIZE);
                conns[i].towBuffer  = (char *)calloc(sizeof(char), 1024);

                conns[i].magic_string[0] = '\0';
                conns[i].towBuffer[0] = 0; 
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

// sends a constant websocket message to a certain WebSocket
void sendToWS(dual_sock_conn* sockConn, char const* msg){
    if (sockConn->fdw){
        sockConn->towBuffer[0] = 0x81;//1000 0001 i.e FIN-bit 0 0 0 Opcode(4 bits)
        sockConn->towBuffer[1] = (unsigned char)strlen(msg);// Payload Len
        memcpy( sockConn->towBuffer + 2, msg, (unsigned char)strlen(msg) + 1 );
    }
}

// sends a close frame to a certain WebSocket
void closeWS (dual_sock_conn* sockConn) {
    if (_VERBOSE_MODE) printf("[socket fd:%d]\tother side closed the socket\n", sockConn->fdw);

    close(sockConn->fdw);

    //if this websocket doesn't have a user to send the close message
    if (!sockConn->fdr){
        int i;
        //try to find a free user for it
        for (i=0; i < _MAX_CLIENT; ++i)
            if ( !conns[i].fdw && conns[i].fdr ){
                sockConn->fdw = sockConn->rtowBuffer[0] = 0;
                sockConn = &conns[i];
                break;
            }
    }

    if (sockConn->fdr){
        char const* msg;

        switch(sockConn->wtorFormat){

            case JSON:
                msg =   "{\"header\":\"error\",\"data\":\""_WS_CLOSED_MESSAGE"\"}";
                break;
            
            case XML:
                msg =   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                        "<tw_msg "
                        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                        "xsi:noNamespaceSchemaLocation=\""_XML_XSD_LOCATION"\">"
                        "<header>error</header>"
                        "<desc>"_WS_CLOSED_MESSAGE"</desc>"
                        "</tw_msg>";
                break;
            
            case UNKNOWN:
                msg =   "error: "_WS_CLOSED_MESSAGE;
                break;

            //case PROLOG:
            default:
                msg =   "tw_msg(header(error), data('"_WS_CLOSED_MESSAGE"')).\n";
        }

        memcpy( sockConn->wtorBuffer, msg, strlen(msg) + 1 );
    }

    sockConn->fdw = sockConn->rtowBuffer[0] = 0;
}

// ready-to-receive (from WebSocket) event handler
void onWSReceiveEventHandler (dual_sock_conn* sockConn) {
    char            buffer[_BUFFER_SIZE];
    uint64_t        payloadLength;
    int             bytesRecv;
    unsigned int    i;
    unsigned char   iMaskingKey, iPayloadData;

    if (_VERBOSE_MODE) printf("[socket fd:%d]\tnew data from the WebSocket was received\n", sockConn->fdw);

    checkIfError(
        bytesRecv = recv(sockConn->fdw, buffer, _BUFFER_SIZE, 0),
        "socket: recv",
        "couldn't receive data",
        false
    );

    // if the other side closed the socket
    if (bytesRecv <= 0)
        closeWS(sockConn);
    else if (_WS_TO_RS_FORWARDING) {
        buffer[bytesRecv] = 0;

        if (_VERBOSE_MODE) printf("[socket fd:%d]\tdata is:\n%s\n", sockConn->fdw, buffer);

        //if this websocket doesn't have a user to exchange data with, try to find a free user for it
        if (!sockConn->fdr){
            for (i=0; i < _MAX_CLIENT; ++i)
                //if a user is waiting for a web socket!
                if ( !conns[i].fdw && conns[i].fdr && sockConn->magic_string[0] &&
                    istrcmp(sockConn->magic_string, conns[i].magic_string))
                {
                    //1 bit is used as a flag to know that this ws is new at this
                    //i-th position and its ready-to-read event was already handled here
                    conns[i].fdw = sockConn->fdw|_FD_HANDLED_FLAG;
                    sockConn->fdw = 0;
                    sockConn = &conns[i];

                    sendToWS(sockConn, _WS_CONNECT_MESSAGE);
                    break;
                }
        }

        /** WEBSOCKET MESSAGE (see section 5 "Data Framing" from the RFC 6455) **/

        switch ( buffer[0]&0x0F /*OpCode*/){

            case 1:{ // Text frame
                unsigned int offset = strlen(sockConn->wtorBuffer + 1);
                char head = sockConn->wtorBuffer[offset];

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

                //if FIN bit is 1
                if (buffer[0]&0x80){
                    char* connectMsg;

                    if (offset == 0)
                        memcpy(sockConn->wtorBuffer, buffer + iPayloadData, payloadLength);
                    else{
                        memcpy(sockConn->wtorBuffer + offset, buffer + iPayloadData, payloadLength);
                        sockConn->wtorBuffer[0] = head;
                    }
                    sockConn->wtorBuffer[offset + payloadLength] = 0;

                    //if it is a "CONNECT" message
                    connectMsg = getConnectMagicString(sockConn->wtorBuffer);

                    if (connectMsg != NULL){
                        *(int *)sockConn->wtorBuffer = 0;
                        int newPos= -1;
                        for (i=0; i < _MAX_CLIENT; ++i){
                            //if the i-th position is empty
                            if ( (!conns[i].fdr && !conns[i].fdw) && newPos == -1 )
                                newPos = i;

                            if  (conns[i].fdr && !conns[i].fdw && istrcmp(connectMsg, conns[i].magic_string)){
                                newPos = i;
                                break;
                            }
                        }

                        if (newPos != -1){
                            conns[newPos].fdw = sockConn->fdw|_FD_HANDLED_FLAG;

                            //creating buffer on demand
                            if (conns[newPos].wtorBuffer == NULL){
                                conns[newPos].wtorBuffer = (char *)calloc(sizeof(char), _BUFFER_SIZE);
                                conns[newPos].rtowBuffer = (char *)calloc(sizeof(char), _BUFFER_SIZE);
                                conns[newPos].towBuffer  = (char *)calloc(sizeof(char), 1024);

                                conns[newPos].magic_string[0] = '\0';
                                conns[newPos].towBuffer[0] = 0; 
                            }

                            sockConn->fdw = 0;
                            sockConn = &conns[newPos];

                            if (conns[newPos].fdr)
                                sendToWS(sockConn, _WS_CONNECT_MESSAGE);
                        }

                        strcpy(sockConn->magic_string, connectMsg);
                    }else
                    if (!sockConn->fdr && _VERBOSE_MODE)
                        printf("[socket fd:%d]\tno raw socket to send data to\n", sockConn->fdw&_FD_MASK);
                }else
                    //if FIN bit is 0
                    if (offset == 0){
                        memcpy(sockConn->wtorBuffer + 1, buffer + iPayloadData + 1, payloadLength-1);
                        sockConn->wtorBuffer[payloadLength] = buffer[iPayloadData];
                        sockConn->wtorBuffer[payloadLength + 1] = 0;
                    }else{
                        memcpy(sockConn->wtorBuffer + offset, buffer + iPayloadData, payloadLength);
                        sockConn->wtorBuffer[offset + payloadLength] = head;
                        sockConn->wtorBuffer[offset + payloadLength+ 1] = 0;
                    }
                break;
            }
            case 8: //Close frame
                closeWS(sockConn);
                break;

            default:{
                char const* reasonMsg = "received type of data cannot be accepted (only text data is accepted)";
                //Close Frame (Data type not allowed)
                sockConn->rtowBuffer[0] = 0x88;//1000 1000 i.e FIN-bit 0 0 0 Opcode(4 bits)

                //Payload len
                *(uint16_t *)&sockConn->rtowBuffer[2] = htons( 1003 );//Status Codes (see RFC 6455 7.4.1. "Defined Status Codes")
                sockConn->rtowBuffer[1] = (unsigned char)(strlen(reasonMsg) + 2);

                sockConn->rtowLen = 2 + sockConn->rtowBuffer[1];

                //sending the close frame
                memcpy(sockConn->rtowBuffer + 4, reasonMsg, sockConn->rtowBuffer[1] - 1);
                }
                break;
        }//switch
    }//if at least one byte was received 
}

// ready-to-receive (from raw socket) event handler
void onRSReceiveEventHandler (dual_sock_conn* sockConn) {
    int             bytesRecv, fdw_i= -1;
    char            buffer[_BUFFER_SIZE];
    unsigned int    i, iPayloadData;

    if (_VERBOSE_MODE) printf("[socket fd:%d]\tnew data from the raw socket was received\n", sockConn->fdr);

    checkIfError(
        bytesRecv = recv(sockConn->fdr, buffer, _BUFFER_SIZE, 0),
        "socket: recv",
        "couldn't receive data from the raw socket",
        false
    );

    // if the other side closed the socket
    if (bytesRecv <= 0){
        if (_VERBOSE_MODE) printf("[socket fd:%d]\tother side closed the socket\n", sockConn->fdr);

        close(sockConn->fdr);

        //if this raw socket doesn't have a websocket to send the close message yet
        if (!sockConn->fdw){
            int i;
            //try to find a free user for it
            for (i=0; i < _MAX_CLIENT; ++i)
                if ( !conns[i].fdr && conns[i].fdw && sockConn->magic_string[0] &&
                    istrcmp(sockConn->magic_string, conns[i].magic_string))
                {
                    sockConn->fdr = sockConn->wtorBuffer[0] = 0;
                    sockConn = &conns[i];

                    ///sendToWS(sockConn, _WS_CONNECT_MESSAGE);
                    break;
                }
        }

        sendToWS(sockConn, _WS_DISCONNECT_MESSAGE);

        sockConn->fdr = sockConn->wtorBuffer[0] = 0;
    }else{
        buffer[bytesRecv] = 0;

        if (_VERBOSE_MODE) printf("[socket fd:%d]\tdata is:\n%s\n", sockConn->fdr, buffer);

        // if what we have received is a web socket message
        if ( !regexec(&regex_wsInitialMsg, buffer, regex_wsInitialMsg.re_nsub+1, matchs, 0) ){
            if (_VERBOSE_MODE) printf("[socket fd:%d]\tWebSocket detected\n", sockConn->fdr);

            for (i=0; i < _MAX_CLIENT; ++i)
                // if a user is waiting for a web socket!
                if ( (conns[i].fdr && !conns[i].fdw) && (conns[i].fdr != sockConn->fdr) &&
                    sockConn->magic_string[0] && istrcmp(sockConn->magic_string, conns[i].magic_string)){
                    //1 bit is used as a flag to know that this ws is new at this
                    //i-th position and its ready-to-read event was already handled here
                    conns[i].fdw = sockConn->fdr|_FD_HANDLED_FLAG;
                    sockConn->fdr = 0;
                    sockConn = &conns[i];

                    sendToWS(sockConn, _WS_CONNECT_MESSAGE);

                    if (_VERBOSE_MODE) printf("[server socket]\tnew dual connection created (ws %d, rs %d)\n", sockConn->fdw&_FD_MASK, sockConn->fdr);
                    break;
                }else
                if (fdw_i == -1 && !conns[i].fdw)
                    fdw_i = i;

            //if wasn't able to found a free user
            if (i >= _MAX_CLIENT){
                //1 bit is used as a flag to know that this ws is new at this
                //fdw_i-th position and its ready-to-read event was already handled here
                conns[fdw_i].fdw = sockConn->fdr|_FD_HANDLED_FLAG;
                sockConn->fdr = 0;
                sockConn = &conns[fdw_i];
                if (_VERBOSE_MODE) printf("[server socket]\tnew WebSocket %d waiting for incoming raw sockets\n", sockConn->fdw&_FD_MASK);
            }

            //WEBSOCKET OPENING HANDSHAKE [RFC 6455 4.2.1-2]
            if (_VERBOSE_MODE) printf("[websocket]\tproceding with opening handshake...\n");
            //1) capturing the Sec-WebSocket-Key value (stores it in fullWebSocketKey)
            if (_VERBOSE_MODE) printf("[websocket]\t\tcapturing the sec-websocket-key value\n");
            if (matchs[2].rm_so == -1)
                memcpy((void *)&matchs[2], (void *)&matchs[3], sizeof(regmatch_t));
            memcpy(fullWebSocketKey, buffer + matchs[2].rm_so, 24);

            //2) concatenating fullWebSocketKey with the GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            if (_VERBOSE_MODE) printf("[websocket]\t\tconcatenating with GUID\n");
            memcpy(fullWebSocketKey + 24, _WS_SPECIFICATION_GUID, 36);

            //3)  taking the SHA-1 hash of this concatenated value to obtain a 20-byte value
            if (_VERBOSE_MODE) printf("[websocket]\t\tcomputing SHA-1 hash\n");
            KeyHash = SHA1(fullWebSocketKey, 60);

            //4) and base64-encoding this 20-byte hash
            base64encode(KeyHash , 20, secWebsocketAccept, 29);

            //5) sending the handshake message to the web socket asynchronously
            if (_VERBOSE_MODE) printf("[websocket]\t\tsending handshake message\n");
            strcpy(
                handshakeMessage,
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: "
            );
            strcat(handshakeMessage, secWebsocketAccept);
            strcat(handshakeMessage, "\r\n\r\n");

            sockConn->rtowLen = strlen(handshakeMessage);
            memcpy( sockConn->rtowBuffer, handshakeMessage, sockConn->rtowLen + 1 );
        }else{
            //if it is a raw socket and doesn't have a ws to exchange data with, try to find a free ws for it
            if (!sockConn->fdw){
                for (i=0; i < _MAX_CLIENT; ++i)
                    //if a raw socket is waiting for a web socket!
                    if ( !conns[i].fdr && conns[i].fdw && sockConn->magic_string[0] &&
                        istrcmp(sockConn->magic_string, conns[i].magic_string))
                    {
                        //1 bit is used as a flag to know that this rs is new at this
                        //i-th position and its ready-to-read event was already handled here
                        conns[i].fdr = sockConn->fdr|_FD_HANDLED_FLAG;
                        sockConn->fdr = 0;
                        sockConn = &conns[i];

                        sendToWS(sockConn, _WS_CONNECT_MESSAGE);
                        break;
                    }
            }
            buffer[bytesRecv] = 0;

            sockConn->rtowBuffer[0] = 0x81;//1000 0001 i.e FIN-bit 0 0 0 Opcode(4 bits)
            iPayloadData = 2;

            //[extended] Payload len
            if (bytesRecv <= 125)
                sockConn->rtowBuffer[1] = (unsigned char)bytesRecv; // & 0x07F; //& 0111 1111 (MASK bit set to 0);
            else{
                sockConn->rtowBuffer[1] = 126;
                *(uint16_t *)&sockConn->rtowBuffer[2] = htons( (uint16_t)bytesRecv );
                iPayloadData+=2; //2 bytes = 16 bits
            }

            sockConn->rtowLen = iPayloadData + bytesRecv;
            //sending data to the websocket asynchronously encapsulated in a websocket frame
            char* connectMsg = getConnectMagicString(buffer);

            if (connectMsg != NULL){
                sockConn->rtowBuffer[0] = 0;
                int newPos = -1;
                for (i=0; i < _MAX_CLIENT; ++i){
                    //if the i-th position is empty
                    if ( (!conns[i].fdr && !conns[i].fdw) && newPos == -1)
                        newPos = i;

                    if  (!conns[i].fdr && conns[i].fdw && istrcmp(connectMsg, conns[i].magic_string)){
                        newPos = i;
                        break;
                    }
                }

                if (newPos != -1){
                    conns[newPos].fdr = sockConn->fdr|_FD_HANDLED_FLAG;

                    //creating buffer on demand
                    if (conns[newPos].wtorBuffer == NULL){
                        conns[newPos].wtorBuffer = (char *)calloc(sizeof(char), _BUFFER_SIZE);
                        conns[newPos].rtowBuffer = (char *)calloc(sizeof(char), _BUFFER_SIZE);
                        conns[newPos].towBuffer  = (char *)calloc(sizeof(char), 1024);

                        conns[newPos].magic_string[0] = '\0';
                        conns[newPos].towBuffer[0] = 0; 
                    }

                    sockConn->fdr = 0;
                    sockConn = &conns[newPos];

                    sendToWS(sockConn, _WS_CONNECT_MESSAGE);
                }
                strcpy(sockConn->magic_string, connectMsg);
            }else
            if (sockConn->fdw)
                memcpy(sockConn->rtowBuffer + iPayloadData, buffer, bytesRecv + 1);
            else
                if (_VERBOSE_MODE) printf("[socket fd:%d]\tno webSocket to send data to\n", sockConn->fdr);
        }
    }
}

// ready-to-send (to raw socket) event handler
void onWStoRSSendEventHandler (dual_sock_conn* sockConn) {
    if (sockConn->wtorBuffer[0]){
        if (_VERBOSE_MODE) printf("[socket fd:%d]\tsends data to the raw socket[%d]:\n%s\n", sockConn->fdw, sockConn->fdr&_FD_MASK, sockConn->wtorBuffer);

        sockConn->wtorFormat = sockConn->wtorBuffer[0];

        write(sockConn->fdr&_FD_MASK, sockConn->wtorBuffer, strlen(sockConn->wtorBuffer));//send
        *(int *)sockConn->wtorBuffer = 0;
    }
}

// ready-to-send (to WebSocket) event handler
void onRStoWSSendEventHandler (dual_sock_conn* sockConn) {
    //Raw socket to websocket messages
    if (sockConn->rtowBuffer[0]){
        if (_VERBOSE_MODE) printf("[socket fd:%d]\tsends data to the WebSocket[%d]:\n%s\n", sockConn->fdr, sockConn->fdw&_FD_MASK, sockConn->rtowBuffer);
        write(sockConn->fdw&_FD_MASK, sockConn->rtowBuffer, sockConn->rtowLen);//send
        sockConn->rtowBuffer[0] = 0;
    }
    //constant string messages
    if (sockConn->towBuffer[0]){
        if (_VERBOSE_MODE) printf("[server socket]\tsends constant messsage to the WebSocket[%d]:\n%s\n", sockConn->fdw&_FD_MASK, sockConn->towBuffer);
        write(sockConn->fdw&_FD_MASK, sockConn->towBuffer, strlen(sockConn->towBuffer));//send
        sockConn->towBuffer[0] = 0;
    }
}

// ...and that's it! =D
