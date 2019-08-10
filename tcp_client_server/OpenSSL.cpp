#include "OpenSSL.h"
#include <openssl\applink.c>
int perror_SSL(int code) {
	switch (code) {
	case SSL_ERROR_SSL:
		printf("SSL_ERROR_SSL");
		return SSL_ERROR_SSL;
	case SSL_ERROR_WANT_READ:
		printf("SSL_ERROR_WANT_READ");
		return SSL_ERROR_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
		printf("SSL_ERROR_WANT_WRITE");
		return SSL_ERROR_WANT_WRITE;
	case SSL_ERROR_WANT_X509_LOOKUP:
		printf("SSL_ERROR_WANT_X509_LOOKUP");
		return SSL_ERROR_WANT_X509_LOOKUP;
	case SSL_ERROR_SYSCALL:
		printf("SSL_ERROR_SYSCALL");
		return SSL_ERROR_SYSCALL;
	case SSL_ERROR_ZERO_RETURN:
		printf("SSL_ERROR_ZERO_RETURN");
		return SSL_ERROR_ZERO_RETURN;
	case SSL_ERROR_WANT_CONNECT:
		printf("SSL_ERROR_WANT_CONNECT");
		return SSL_ERROR_WANT_CONNECT;
	case SSL_ERROR_WANT_ACCEPT:
		printf("SSL_ERROR_WANT_ACCEPT");
		return SSL_ERROR_WANT_ACCEPT;
	}
	return SSL_ERROR_NONE;
}
void InitContextSSL(SSL_info* data) {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
	data->method = TLSv1_2_client_method();
	data->ctx = SSL_CTX_new(data->method);
	SSL_CTX_set_options(data->ctx, SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_options(data->ctx, SSL_OP_TLS_ROLLBACK_BUG);
	SSL_CTX_set_mode(data->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
}
void InstallCertificate(SSL_info* data)
{
	SSL_CTX_set_ecdh_auto(data->ctx, 1);
	if (SSL_CTX_use_certificate_file(data->ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(data->ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_check_private_key(data->ctx)) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

void InitClientSSL(SSL_info* data, SOCKET socket) {
	
	if ((data->cSSL = SSL_new(data->ctx)) == NULL ||
		SSL_set_fd(data->cSSL, socket) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	int ret, err;
	if ((ret = SSL_connect(data->cSSL)) <= 0) {
		ret = SSL_get_error(data->cSSL, ret);
		if ((err = ERR_get_error())) {
			fprintf(stderr, "SSL connect err code:[%lu](%s)\n", err, ERR_error_string(err, NULL));
		}
	}
}
int RecvOpenSSLPacket(SSL_info* data)
{
	int length = 100;
	char info[101] = { 0 };
	do {
		length = SSL_read(data->cSSL, info, length);
		printf(info);
	} while (length > 0);
	return ERROR_SSL(data->cSSL, (data->cSSL, length));
}
int SendOpenSLLPacket(SSL_info* data, const char* buf)
{
	return ERROR_SSL(data->cSSL, SSL_write(data->cSSL, buf, strlen(buf)));
}
void ClearContextSSL(SSL_info* data) {
	SSL_CTX_free(data->ctx);
}
void ShutdownSSL(SSL_info* data) {
	SSL_shutdown(data->cSSL);
	SSL_free(data->cSSL);
	if (!SSL_clear(data->cSSL))
		printf("Error: SSL_clear!");

}
void DestroySSL() {
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	//ERR_remove_state();
	ERR_free_strings();
}