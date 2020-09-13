#include <cstdio>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <csignal>
#include <algorithm>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <atomic>

#define MAX_MSG_LENGTH 65535
#define BUFFER_SIZE 8192
#define DISCOVER 1
#define IAM 2
#define KEEPALIVE 3
#define AUDIO 4
#define METADATA 6
#define CLIENT_HEADER_LENGTH 4

using namespace std;

struct Parameters
{
    string host;
    string resource;
    string streamPort;
    string clientPort;
    string multicastAddress;
    bool metaData = false;
    unsigned long streamTimeout = 5;
    unsigned long clientTimeout = 5;
};

struct Client
{
    sockaddr_in addrInfo;
    chrono::time_point<chrono::system_clock> lastKeepAliveTime;
};

mutex dataMutex;

// mutex that locks next access to critical section
mutex nextMutex;

// first - client address
unordered_map<in_addr_t, Client> clients;

// flag that tells whether radio stream should end
volatile atomic<bool> stream(true);

static void catchInt(int sig)
{
    if (sig == SIGINT)
    {
        stream = false;
    }
    else
    {
        cerr << "ERROR: Unknown signal received at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }
}

void addSigaction()
{
    struct sigaction action{};
    sigset_t block_mask;

    sigemptyset(&block_mask);
    action.sa_handler = catchInt;
    action.sa_mask = block_mask;
    action.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &action, nullptr) == -1)
    {
        cerr << "ERROR: sigaction at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }
}

Parameters getParameters(int argc, const char *const argv[])
{
    if (argc % 2 == 0)
    {
        cerr << "ERROR: wrong arguments at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    bool isHost = false;
    bool isResource = false;
    bool isStreamPort = false;
    bool isClientPort = false;
    bool isMulticastAddress = false;
    bool isClientTimeout = false;

    Parameters parameters;

    int index = 1;

    while (index < argc - 1)
    {
        if (strcmp(argv[index], "-h") == 0)
        {
            isHost = true;
            index++;
            parameters.host.assign(argv[index]);
        }
        else if (strcmp(argv[index], "-r") == 0)
        {
            isResource = true;
            index++;
            parameters.resource.assign(argv[index]);
        }
        else if (strcmp(argv[index], "-p") == 0)
        {
            isStreamPort = true;
            index++;
            parameters.streamPort.assign(argv[index]);
        }
        else if (strcmp(argv[index], "-m") == 0)
        {
            index++;
            if (strcmp(argv[index], "yes") == 0)
            {
                parameters.metaData = true;
            }
            else if (strcmp(argv[index], "no") == 0)
            {
                parameters.metaData = false;
            }
            else
            {
                cerr << "ERROR: wrong arguments at line " << __LINE__ << "\n";
                exit(EXIT_FAILURE);
            }
        }
        else if (strcmp(argv[index], "-t") == 0)
        {
            index++;
            string streamTimeoutStr(argv[index]);
            parameters.streamTimeout = stoul(streamTimeoutStr, nullptr, 10);
            if (parameters.streamTimeout == 0)
            {
                cerr << "ERROR: wrong arguments at line " << __LINE__ << "\n";
                exit(EXIT_FAILURE);
            }
        }
        else if (strcmp(argv[index], "-P") == 0)
        {
            index++;
            isClientPort = true;
            parameters.clientPort.assign(argv[index]);
        }
        else if (strcmp(argv[index], "-B") == 0)
        {
            index++;
            isMulticastAddress = true;
            parameters.multicastAddress.assign(argv[index]);
        }
        else if (strcmp(argv[index], "-T") == 0)
        {
            index++;
            isClientTimeout = true;
            string clientTimeoutStr(argv[index]);
            parameters.clientTimeout = stoul(clientTimeoutStr, nullptr, 10);
            if (parameters.clientTimeout == 0)
            {
                cerr << "ERROR: wrong arguments at line " << __LINE__ << "\n";
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            cerr << "ERROR: wrong arguments at line " << __LINE__ << "\n";
            exit(EXIT_FAILURE);
        }
        index++;
    }

    if (!isHost || !isResource || !isStreamPort ||
        (!isClientPort && (isMulticastAddress || isClientTimeout)))
    {
        cerr << "ERROR: wrong arguments at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    return parameters;
}

// Creates socket that connects to radio.
int socketConnect(const Parameters &parameters)
{
    int retValue;
    int sock;
    struct addrinfo addrHints{}, *addrResult;

    addrHints.ai_flags = 0;
    addrHints.ai_family = AF_INET;
    addrHints.ai_socktype = SOCK_STREAM;
    addrHints.ai_protocol = IPPROTO_TCP;

    retValue = getaddrinfo(parameters.host.c_str(), parameters.streamPort.c_str(), &addrHints,
                           &addrResult);
    if (retValue != 0)
    {
        cerr << "ERROR: getaddrinfo at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    sock = socket(addrResult->ai_family, addrResult->ai_socktype, addrResult->ai_protocol);
    if (sock < 0)
    {
        cerr << "ERROR: creating socket at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    struct timeval tv{};
    tv.tv_sec = parameters.streamTimeout;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv, sizeof(tv)) != 0)
    {
        cerr << "ERROR: setsockopt at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    if (connect(sock, addrResult->ai_addr, addrResult->ai_addrlen) != 0)
    {
        cerr << "ERROR: connect at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(addrResult);

    return sock;
}

// Returns http request. Memory needs to be freed.
char *buildRequest(const Parameters &parameters)
{
    string metaDataHeader;

    if (parameters.metaData)
    {
        metaDataHeader = "Icy-MetaData:1\r\n";
    }
    else
    {
        metaDataHeader = "";
    }

    unsigned long bufferSize = (strlen("GET  HTTP/1.0\r\n")
                                + parameters.resource.length()
                                + strlen("Host: \r\n")
                                + parameters.host.length()
                                + metaDataHeader.length()
                                + strlen("Connection: close\r\n")
                                + strlen("\r\n") + 1);

    char *request = new char[bufferSize];

    int retVal;

    retVal = snprintf(request, bufferSize, "GET %s HTTP/1.0\r\n"
                                           "Host: %s\r\n"
                                           "%s"
                                           "Connection: close\r\n\r\n",
                      parameters.resource.c_str(), parameters.host.c_str(),
                      metaDataHeader.c_str());

    if (retVal < 0 || (unsigned) retVal > bufferSize)
    {
        printf("%d", retVal);
        cerr << "ERROR: at line " << __LINE__ << "increase bufferSize\n";
        exit(EXIT_FAILURE);
    }

    return request;
}

// Reads exactly count number of bytes from fd. If it can't be done exits the program.
void safeRead(int fd, void *buffer, size_t count)
{
    int bytesReceived;
    size_t index = 0;
    char *buf = (char *) buffer;

    while (index < count)
    {
        bytesReceived = read(fd, &(buf[index]), count - index);

        if (bytesReceived == 0)
        {
            cerr << "ERROR: end of stream at line " << __LINE__ << "\n";
            exit(EXIT_FAILURE);
        }
        else if (bytesReceived < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                cerr << "ERROR: failed read at line " << __LINE__ << "\n";
                exit(EXIT_FAILURE);
            }
        }
        index += bytesReceived;
    }
}

// Reads http response header from socket and returns it
string getHeader(int socket)
{
    char *buffer = new char();
    string header;

    while (header.length() < strlen("\r\n\r\n")
           || header.compare(header.length() - strlen("\r\n\r\n"),
                             strlen("\r\n\r\n"), "\r\n\r\n") != 0)
    {
        safeRead(socket, buffer, 1);
        header.push_back(*buffer);
    }

    delete buffer;
    return header;
}

// Checks if http response status is correct.
// If not ends the program.
void checkStatus(const string &header)
{
    size_t statusStart = 0;
    size_t statusEnd;
    string status;

    statusEnd = header.find("\r\n", statusStart);
    if (statusEnd == std::string::npos)
    {
        cerr << "ERROR: wrong header at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }
    statusEnd--;
    status = header.substr(statusStart, statusEnd - statusStart + 1);

    if (status != "ICY 200 OK" && status != "HTTP/1.0 200 OK" && status != "HTTP/1.1 200 OK")
    {
        cerr << "incorrect status: " << status << " at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }
}

// Sets metaDataInterval to "icy-metaint:" value, or to 0 if no "icy-metaint:".
// Sets radioName to "icy-name:" value, or to "" if no "icy-name:".
void getHeaderData(const string &header, unsigned long &metaDataInterval, string &radioName)
{
    size_t lineStart = 0;
    size_t lineEnd;
    string line;
    string lowerCaseLine;

    metaDataInterval = 0;
    radioName = "";

    while (lineStart < header.length())
    {
        lineEnd = header.find("\r\n", lineStart);
        if (lineEnd == std::string::npos)
        {
            cerr << "ERROR: wrong header at line " << __LINE__ << "\n";
            exit(EXIT_FAILURE);
        }
        lineEnd += strlen("\r\n") - 1;
        line = header.substr(lineStart, lineEnd - lineStart + 1);

        lowerCaseLine = line;
        transform(lowerCaseLine.begin(), lowerCaseLine.end(), lowerCaseLine.begin(), ::tolower);

        if (lowerCaseLine.find("icy-metaint:") == 0)
        {
            size_t metaIntStart = strlen("icy-metaint:");
            size_t metaIntEnd = lowerCaseLine.find("\r\n");
            if (metaIntEnd == std::string::npos)
            {
                cerr << "ERROR: wrong header at line " << __LINE__ << "\n";
                exit(EXIT_FAILURE);
            }
            metaIntEnd--;

            string metaIntStr = line.substr(metaIntStart, metaIntEnd - metaIntStart + 1);
            metaDataInterval = stoul(metaIntStr, nullptr, 10);
        }

        if (lowerCaseLine.find("icy-name:") == 0)
        {
            size_t radioNameStart = strlen("icy-name:");
            size_t radioNameEnd = lowerCaseLine.find("\r\n");
            if (radioNameEnd == std::string::npos)
            {
                cerr << "ERROR: wrong header at line " << __LINE__ << "\n";
                exit(EXIT_FAILURE);
            }
            radioNameEnd--;

            radioName = line.substr(radioNameStart, radioNameEnd - radioNameStart + 1);
        }

        lineStart = lineEnd + 1;
    }
}

// Creates socket for communication with clients.
int clientSocketConnect(const Parameters &parameters)
{
    in_port_t localPort;
    int sock;
    struct sockaddr_in localAddress{};
    struct ip_mreq ipMreq{};

    localPort = (in_port_t) stoul(parameters.clientPort, nullptr, 10);

    // initialise socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        cerr << "ERROR: socket at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    struct timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv, sizeof(tv)) != 0)
    {
        cerr << "ERROR: setsockopt at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    // connect to multicast group
    if (!parameters.multicastAddress.empty())
    {
        ipMreq.imr_interface.s_addr = htonl(INADDR_ANY);
        if (inet_aton(parameters.multicastAddress.c_str(), &ipMreq.imr_multiaddr) == 0)
        {
            cerr << "ERROR: inet_aton - invalid multicast address at line " << __LINE__ << "\n";
            exit(EXIT_FAILURE);
        }
        if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &ipMreq, sizeof ipMreq)
            < 0)
        {
            cerr << "ERROR: setsockopt at line " << __LINE__ << "\n";
            exit(EXIT_FAILURE);
        }
    }

    // set address and local port
    localAddress.sin_family = AF_INET;
    localAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddress.sin_port = htons(localPort);
    if (bind(sock, (struct sockaddr *) &localAddress, sizeof localAddress) < 0)
    {
        cerr << "ERROR: bind at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    return sock;
}

// Returns true if message was sent, false if it failed to send it.
bool sendMsgToClient(int clientSocket, const char *data, uint16_t dataLength, uint16_t msgType,
                     sockaddr_in addrInfo)
{
    uint8_t msgTypeMoreSignificantByte = msgType >> 8;
    uint8_t msgTypeLessSignificantByte = msgType & 0xFF;
    uint8_t dataLengthMoreSignificantByte = dataLength >> 8;
    uint8_t dataLengthLessSignificantByte = dataLength & 0xFF;
    size_t messageLength = dataLength + CLIENT_HEADER_LENGTH;
    auto *message = new char[messageLength];
    int bytesSent;

    // fill 4 first bytes of message with msgType and dataLength Big Endian order
    message[0] = msgTypeMoreSignificantByte;
    message[1] = msgTypeLessSignificantByte;
    message[2] = dataLengthMoreSignificantByte;
    message[3] = dataLengthLessSignificantByte;
    memcpy(&(message[5]), data, dataLength);

    bytesSent = sendto(clientSocket, message, messageLength, 0,
                       (struct sockaddr *) &(addrInfo), (socklen_t) sizeof(sockaddr_in));
    delete[] message;

    if (bytesSent >= 0 && (size_t) bytesSent == messageLength)
    {
        return true;
    }
    else
    {
        return false;
    }
}

// Sends message to all clients.
void sendToClients(int clientSocket, const char *data, uint16_t dataLength, uint16_t msgType,
                   unsigned long clientTimeout)
{
    long elapsedTime;

    nextMutex.lock();
    dataMutex.lock();
    nextMutex.unlock();

    for (auto client : clients)
    {
        elapsedTime = chrono::duration_cast<chrono::seconds>
                (chrono::system_clock::now() - client.second.lastKeepAliveTime).count();

        if (elapsedTime > 0 && (unsigned long) elapsedTime > clientTimeout)
        {
            clients.erase(client.first);
            continue;
        }

        if (!sendMsgToClient(clientSocket, data, dataLength,
                             msgType, client.second.addrInfo))
        {
            clients.erase(client.first);
        }
    }

    dataMutex.unlock();
}

// Streams radio without metadata.
void sendOutputWithoutMetadata(int socket, int clientSocket, bool withClients,
                               unsigned long clientTimeout)
{
    char buffer[BUFFER_SIZE];

    while (stream)
    {
        safeRead(socket, buffer, BUFFER_SIZE);

        if (withClients)
        {
            sendToClients(clientSocket, buffer, BUFFER_SIZE, AUDIO, clientTimeout);
        }
        else
        {
            string output(buffer, BUFFER_SIZE);
            cout << output;
        }
    }
}

void sendMetadata(int socket, int clientSocket, bool withClients, unsigned long clientTimeout)
{
    char buffer[MAX_MSG_LENGTH];
    uint8_t lengthBuffer[1];
    uint16_t metaDataLength;

    safeRead(socket, lengthBuffer, 1);
    metaDataLength = lengthBuffer[0] * 16;
    if (metaDataLength == 0)
    {
        return;
    }

    safeRead(socket, buffer, metaDataLength);

    if (withClients)
    {
        sendToClients(clientSocket, buffer, metaDataLength, METADATA, clientTimeout);
    }
    else
    {
        string output(buffer, metaDataLength);
        cerr << output;
    }

}

// Streams radio with metadata.
void sendOutputWithMetadata(int socket, unsigned long metaDataInterval, int clientSocket,
                            bool withClients, unsigned long clientTimeout)
{
    char buffer[BUFFER_SIZE];
    unsigned long index;

    while (stream)
    {
        index = 0;
        while (stream && metaDataInterval - index > BUFFER_SIZE)
        {
            safeRead(socket, buffer, BUFFER_SIZE);
            if (withClients)
            {
                sendToClients(clientSocket, buffer, BUFFER_SIZE, AUDIO, clientTimeout);
            }
            else
            {
                string output(buffer, BUFFER_SIZE);
                cout << output;
            }
            index += BUFFER_SIZE;
        }

        if (stream)
        {
            safeRead(socket, buffer, metaDataInterval - index);
            if (withClients)
            {
                sendToClients(clientSocket, buffer, metaDataInterval - index, AUDIO,
                              clientTimeout);
            }
            else
            {
                string output(buffer, metaDataInterval - index);
                cout << output;
            }
            sendMetadata(socket, clientSocket, withClients, clientTimeout);
        }
    }
}

void sendOutput(int socket, unsigned long metaDataInterval, int clientSocket, bool withClients,
                unsigned long clientTimeout)
{
    if (metaDataInterval == 0)
    {
        sendOutputWithoutMetadata(socket, clientSocket, withClients, clientTimeout);
    }
    else
    {
        sendOutputWithMetadata(socket, metaDataInterval, clientSocket, withClients, clientTimeout);
    }
}

// Receives messages from clients and responds accordingly.
void talkWithClients(int clientSocket, const string &radioName)
{
    unsigned char buffer[CLIENT_HEADER_LENGTH];
    sockaddr_in srcAddr{};
    auto addrLen = (socklen_t) sizeof(srcAddr);
    uint16_t dataLength;
    uint16_t msgType;
    uint8_t msgTypeMoreSignificantByte;
    uint8_t msgTypeLessSignificantByte;
    uint8_t dataLengthMoreSignificantByte;
    uint8_t dataLengthLessSignificantByte;

    while (stream)
    {
        if (recvfrom(clientSocket, buffer, CLIENT_HEADER_LENGTH, MSG_WAITALL,
                     (struct sockaddr *) &srcAddr, &addrLen) != CLIENT_HEADER_LENGTH)
        {
            continue;
        }

        // read 4 first bytes of message as msgType and dataLength Big Endian order
        msgTypeMoreSignificantByte = buffer[0];
        msgTypeLessSignificantByte = buffer[1];
        dataLengthMoreSignificantByte = buffer[2];
        dataLengthLessSignificantByte = buffer[3];

        msgType = ((uint16_t) msgTypeMoreSignificantByte) << 8
                  | msgTypeLessSignificantByte;
        dataLength = ((uint16_t) dataLengthMoreSignificantByte) << 8
                     | dataLengthLessSignificantByte;

        //all supported client messages have dataLength 0
        if (dataLength != 0)
        {
            continue;
        }

        nextMutex.lock();
        dataMutex.lock();
        nextMutex.unlock();

        if (msgType == DISCOVER)
        {
            // check if client is already manned
            if (clients.find(srcAddr.sin_addr.s_addr) == clients.end())
            {
                clients.insert({srcAddr.sin_addr.s_addr,
                                {srcAddr, chrono::system_clock::now()}});

                if (!sendMsgToClient(clientSocket, radioName.c_str(), radioName.length(), IAM,
                                     srcAddr))
                {
                    clients.erase(srcAddr.sin_addr.s_addr);
                }
            }
            else
            {
                auto client = clients.find(srcAddr.sin_addr.s_addr);
                client->second.lastKeepAliveTime = chrono::system_clock::now();
            }
        }
        else if (msgType == KEEPALIVE)
        {
            if (clients.find(srcAddr.sin_addr.s_addr) == clients.end())
            {
                cerr << "ERROR: msg from unknown client at line " << __LINE__ << "\n";
                exit(EXIT_FAILURE);
            }
            else
            {
                auto client = clients.find(srcAddr.sin_addr.s_addr);
                client->second.lastKeepAliveTime = chrono::system_clock::now();
            }
        }
        dataMutex.unlock();
    }
}

// If socket is open closes it and sets its value to -1. If it can't be done exits the program
void safeClose(int &socket)
{
    if (socket >= 0)
    {
        if (close(socket) < 0)
        {
            if (errno == EINTR)
            {
                if (close(socket) < 0)
                {
                    cerr << "ERROR: closing socket at line " << __LINE__ << "\n";
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                cerr << "ERROR: closing socket at line " << __LINE__ << "\n";
                exit(EXIT_FAILURE);
            }
        }
        socket = -1;
    }
}

void streamRadio(int socket, const Parameters &parameters)
{
    string header = getHeader(socket);
    checkStatus(header);

    unsigned long metaDataInterval;
    string radioName;

    getHeaderData(header, metaDataInterval, radioName);

    if (metaDataInterval != 0 && !parameters.metaData)
    {
        cerr << "ERROR: response with metadata when request with no metadata at line " << __LINE__
             << "\n";
        exit(EXIT_FAILURE);
    }

    int clientSocket = -1;
    bool withClients;

    if (parameters.clientPort.empty())
    {
        withClients = false;
    }
    else
    {
        withClients = true;
    }

    if (withClients)
    {
        clientSocket = clientSocketConnect(parameters);
        thread talkThread(talkWithClients, clientSocket, radioName);
        thread sendThread(sendOutput, socket, metaDataInterval, clientSocket,
                          withClients, parameters.clientTimeout);
        talkThread.join();
        sendThread.join();
    }
    else
    {
        sendOutput(socket, metaDataInterval, clientSocket, withClients, parameters.clientTimeout);
    }

    safeClose(clientSocket);
}

int main(int argc, char *argv[])
{
    addSigaction();

    Parameters parameters = getParameters(argc, argv);
    int socket;

    socket = socketConnect(parameters);

    char *request = buildRequest(parameters);

    if (write(socket, request, strlen(request) + 1) < 0)
    {
        cerr << "ERROR: writing on stream socket at line " << __LINE__ << "\n";
        exit(EXIT_FAILURE);
    }

    streamRadio(socket, parameters);
    safeClose(socket);

    delete[] request;
    return 0;
}
