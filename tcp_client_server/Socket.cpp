#include "Socket.h"

void getSocketError() {
	TCHAR* s = NULL;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)& s, 0, NULL);
	_tprintf(TEXT("Error: %s\n"), s);
	LocalFree(s);
}

void StartWinSock(WSADATA* ws_data) {
	if (FAILED(WSAStartup(MAKEWORD(2, 2), ws_data)))
		getSocketError();
	else
		printf("Success: WSAStartup!\n");
}
void CreateSocket(socket_data* socket_info, int family, int sock_type, int protocol) {
	socket_info->hints.ai_family = family;
	socket_info->hints.ai_socktype = sock_type;
	socket_info->hints.ai_protocol = protocol;
	if (INVALID_SOCKET == (socket_info->_socket = socket(socket_info->hints.ai_family, socket_info->hints.ai_socktype, socket_info->hints.ai_protocol)))
		getSocketError();
	else
		printf("Success: CreateTCPSocket!\n");
}
void ConnectSocket(socket_data* socket_info, int family, int port, const TCHAR* ip_address) {
	socket_info->addr.sin_family = family;
	socket_info->addr.sin_port = htons(port);
	if (InetPton(family, ip_address, &socket_info->addr.sin_addr.s_addr)) {
		if (SOCKET_ERROR == connect(socket_info->_socket, (sockaddr*)& socket_info->addr, sizeof(socket_info->addr)))
			getSocketError();
	}
	else
		getSocketError();
}
void BindSocket(socket_data* socket_info, unsigned short port, int family, const TCHAR* address)
{
	socket_info->addr.sin_family = family;
	socket_info->addr.sin_port = htons(port);
	if (InetPton(family, address, &socket_info->addr.sin_addr.s_addr)) {
		if (bind(socket_info->_socket, (LPSOCKADDR)& socket_info->addr, sizeof(socket_info->addr)) == SOCKET_ERROR)
			getSocketError();
		else
			printf("Success: BindSocket!\n");
	}
	else {
		getSocketError();
	}
}
void SendSocketMessage(socket_data* socket_info, char* data, size_t size_data)
{
	if (SOCKET_ERROR == send(socket_info->_socket, data, size_data, 0))
		getSocketError();
}
void GetSocketMessage(socket_data* socket_info, char* data, size_t size_data)
{
	int bytes_received = 0;
	do
	{
		int bytes_received = recv(socket_info->_socket, (char*) data, size_data, 0);
		if (SOCKET_ERROR == bytes_received)
		{
			int res = WSAGetLastError();
			if (res != WSAEWOULDBLOCK) return;
			else bytes_received = 1;
		}
		else
			for (int i = 0; i < bytes_received; i++)
				printf("%c", data[i]);
	} while (bytes_received != 0);
}
void SetNonBlockMode(socket_data* socket_info)
{
	u_long argument = TRUE;
	if (SOCKET_ERROR == ioctlsocket(socket_info->_socket, FIONBIO, &argument))
		getSocketError();
}
void ListenSocket(socket_data* socket_info)
{
	if (listen(socket_info->_socket, SOMAXCONN)) {
		getSocketError();
		return;
	}
	else
		printf("Success: Listen Socket!\n");
	sockaddr_in client;
	int client_size = sizeof(client);
	GetLocalIP(socket_info);
	SOCKET client_socket = accept(socket_info->_socket, (sockaddr*)& client, &client_size);
	if (client_socket == INVALID_SOCKET)
		getSocketError();
	char host[NI_MAXHOST] = { 0 };
	char service[NI_MAXHOST] = { 0 };
	if (getnameinfo((sockaddr*)& client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0) {
		printf("%s connected on port %s\n", host, service);
	}
	else {
		inet_ntop(socket_info->hints.ai_family, &client.sin_addr, host, NI_MAXHOST);
		printf("%s connected on port %d\n", host, ntohs(client.sin_port));
	}
	char buffer[4096] = { 0 };
	while (true) {
		memset(buffer, 0, sizeof(buffer));
		int bytesReceived = recv(client_socket, buffer, sizeof(buffer), 0);
		if (bytesReceived == SOCKET_ERROR) {
			getSocketError();
			break;
		}
		else if (bytesReceived == 0)
			break;
		send(client_socket, buffer, bytesReceived, 0);
	}
	closesocket(client_socket);
}

void CloseSocket(socket_data* socket_info)
{
	if (INVALID_SOCKET == (closesocket(socket_info->_socket)))
		getSocketError();
	else
		printf("Success: CloseTCPSocket!\n");
}
void GetHostName(char* host_name, size_t length)
{
	if (gethostname(host_name, length))
		getSocketError();
	else {
		printf("Success: GetHostName!\n Result: %s\n", host_name);
	}
}
void GetLocalIP(socket_data* socket_info)
{
	struct addrinfo* addrs;
	CHAR host_name[64];
	CHAR port_str[16] = {};
	TCHAR ipstringbuffer[46] = { 0 };
	DWORD ipbufferlength = 46;
	GetHostName(host_name, sizeof(host_name));

	if (getaddrinfo(host_name, port_str, &socket_info->hints, &addrs) != NULL)
	{
		for (addrinfo* ptr_addrs = addrs; ptr_addrs != NULL; ptr_addrs = ptr_addrs->ai_next) {
			printf("\tFlags: 0x%x\n", ptr_addrs->ai_flags);
			printf("\tFamily: ");
			switch (ptr_addrs->ai_family) {
			case AF_UNSPEC:
				printf("Unspecified\n");
				break;
			case AF_INET:
				memcpy(&((struct sockaddr_in*) ptr_addrs->ai_addr)->sin_addr, ipstringbuffer, sizeof(IN_ADDR));
				InetNtop(AF_INET, ipstringbuffer, ipstringbuffer, sizeof(IN_ADDR));
				_tprintf(TEXT("AF_INET (IPv4)\n \tIPv4 address %s\n"), ipstringbuffer);
				break;
			case AF_INET6:
				printf("AF_INET6 (IPv6)\n");
				if (WSAAddressToString((LPSOCKADDR)ptr_addrs->ai_addr, (DWORD)ptr_addrs->ai_addrlen, NULL, ipstringbuffer, &ipbufferlength))
					getSocketError();
				else
					_tprintf(TEXT("\tIPv6 address %s\n"), ipstringbuffer);
				break;
			case AF_NETBIOS:
				printf("AF_NETBIOS (NetBIOS)\n");
				break;
			default:
				printf("Other %ld\n", ptr_addrs->ai_family);
				break;
			}
			printf("\tSocket type: ");
		}
	}
}
void StopWinSock() {
	if (WSACleanup())
		getSocketError();
	else
		printf("Success: WSACleanup!\n");
}