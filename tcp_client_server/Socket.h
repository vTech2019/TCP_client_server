#pragma once
#include <winsock2.h>
#include <Ws2tcpip.h>
#include < tchar.h>
#include <fcntl.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32")
struct socket_data {
	addrinfo hints;
	sockaddr_in addr;
	SOCKET _socket;
};
void getSocketError();
void StartWinSock(WSADATA* ws_data);
void CreateSocket(socket_data* socket_info, int family, int sock_type, int protocol);
void ConnectSocket(socket_data* socket_info, int family, int port, const TCHAR* ip_address);

//void ConnectSocket(socket_data* socket_info, const char* address);
void BindSocket(socket_data* socket_info, unsigned short port, int family, const TCHAR* address);
void SendSocketMessage(socket_data* socket_info, char* data, size_t size_data);
void GetSocketMessage(socket_data* socket_info, char* data, size_t size_data);
void SetNonBlockMode(socket_data* socket_info);
void ListenSocket(socket_data* socket_info);
void CloseSocket(socket_data* socket_info);
void GetHostName(char* host_name, size_t length);
void GetLocalIP(socket_data* socket_info);
void StopWinSock();