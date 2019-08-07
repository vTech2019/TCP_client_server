// Miner.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <locale.h>
#include <thread>
#include "Socket.h"

int port = 54000;
const TCHAR* ip_address = TEXT("127.0.0.1");
void Server() {
	socket_data socket_info = { 0 };
	CreateSocket(&socket_info, AF_INET, SOCK_STREAM, IPPROTO_TCP);
	BindSocket(&socket_info, port, AF_INET, INADDR_ANY);
	ListenSocket(&socket_info);
	CloseSocket(&socket_info);
}
void Client() {
	char host_name[64] = { 0 };
	GetHostName(host_name, sizeof(host_name));
	socket_data socket_info = { 0 };
	CreateSocket(&socket_info, AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ConnectSocket(&socket_info, AF_INET, port, ip_address);
	SendSocketMessage(&socket_info, host_name, sizeof(host_name));
	GetSocketMessage(&socket_info, host_name, sizeof(host_name));
	CloseSocket(&socket_info);
}
int main()
{
	WSADATA ws_data;
	StartWinSock(&ws_data);
	setlocale(LC_ALL, "RU");
	std::thread first(Server);
	std::thread second(Client);
	second.join();
	first.join();
	StopWinSock();
	return 0;
}