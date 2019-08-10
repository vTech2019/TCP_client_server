#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "include/openssl/opensslv.h"
#include "include/openssl/ssl.h"
#include "include/openssl/err.h"
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
struct SSL_info {
	const SSL_METHOD* method;
	SSL_CTX* ctx;
	SSL* cSSL;
};
int perror_SSL(int code);
#define ERROR_SSL(ssl, code) perror_SSL(SSL_get_error(ssl, code))
#define CHK_ERR(error, info) if ((error)==-1) { perror(info); exit(EXIT_FAILURE); }

void InitContextSSL(SSL_info* data);
void InstallCertificate(SSL_info* data);
void InitClientSSL(SSL_info* data, SOCKET socket);
int RecvOpenSSLPacket(SSL_info* data);
int SendOpenSLLPacket(SSL_info* data, const char* buf);
void ClearContextSSL(SSL_info* data);
void ShutdownSSL(SSL_info* data);
void DestroySSL();
