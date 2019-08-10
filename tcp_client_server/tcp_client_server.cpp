// Miner.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <locale.h>
#include <thread>
#include "Socket.h"
#include "OpenSSL.h"
char request[] = "GET /main/api/v2/exchangeRate/list/ HTTP/1.1\r\n""Host: api2.nicehash.com\r\n\r\n";
//int port = 54000;
//const TCHAR* ip_address = TEXT("127.0.0.1");
const CHAR* host = "api2.nicehash.com";
int port = 443;
void Server() {
	socket_info socket_info = { 0 };
	CreateSocket(&socket_info, AF_INET, SOCK_STREAM, IPPROTO_TCP);
	BindSocket(&socket_info, port, AF_INET, INADDR_ANY);
	ListenSocket(&socket_info);
	CloseSocket(&socket_info);
}
void Client() {
	char port[] = { "80" };
	socket_info socket_info = { 0 };
	SSL_info SSL_info = { 0 };
	InitContextSSL(&SSL_info);

	ConnectSocket(&socket_info, port, host);
	InitClientSSL(&SSL_info, socket_info._socket);
	InstallCertificate(&SSL_info);
	SendOpenSLLPacket(&SSL_info, request);
	RecvOpenSSLPacket(&SSL_info);


	//SendSocketMessage(&socket_info, request, sizeof(request));
	//GetSocketMessage(&socket_info, request, sizeof(request));
	CloseSocket(&socket_info);
	ShutdownSSL(&SSL_info);
	ClearContextSSL(&SSL_info);
	DestroySSL();
}
int main()
{
	WSADATA ws_data;
	StartWinSock(&ws_data);
	setlocale(LC_ALL, "RU");
	//std::thread first(Server);
	std::thread second(Client);
	second.join();
	//first.join();
	StopWinSock();
	return 0;
}