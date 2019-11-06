/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

typedef unsigned int size_t;
#include "includes.h"

#include "os.h"
#include "base64.h"
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = os_malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	os_memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = os_malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					os_free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}
#include <openssl/evp.h>
#include <openssl/aes.h>

void do_encrypt(unsigned char* key, 
                unsigned char* iv, 
                int do_encrypt,
                char* inbuf,
                int inlen,
                char* outbuf,
                int* outlen)
{
    EVP_CIPHER_CTX *ctx;
    int tmplen;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    if(!EVP_CipherUpdate(ctx, outbuf, outlen, inbuf, inlen))
        printf("problem with cipher update\n");

    printf("length after decrypt/encrypt is %d\n", *outlen);

    if(!EVP_CipherFinal_ex(ctx, outbuf + *outlen, &tmplen))
        printf("problem with cipher final\n");

    printf("length after final is %d\n", tmplen);

    *outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
}

void main(void)
{
    char input[] = "123456789012345";
    char output[(sizeof(input)/sizeof(input[0]) + EVP_MAX_BLOCK_LENGTH)];
    int outlen;

    char output2[(sizeof(input)/sizeof(input[0]) + EVP_MAX_BLOCK_LENGTH)];
    int outlen2;

    char* base64Encode;
    size_t encodeLen;
    char* base64Decode;
    size_t decodeLen;

    unsigned char key[] = "0123456789abcdeF";
    unsigned char iv[] = "1234567887654321";

    printf("input size:%d, output size%d\n", sizeof(input), sizeof(output));

    do_encrypt(key, iv, 1, input, sizeof(input), output, &outlen);
    base64Encode = base64_encode(output, outlen, &encodeLen);

    printf("\n\n encryption output:%s\tbase64 encoding output:%s\n", output, base64Encode);
    printf("encryption length:%d\tbase64 encoding length:%d\n", outlen, encodeLen);

    base64Decode = base64_decode(base64Encode, encodeLen, &decodeLen);
    do_encrypt(key, iv, 0, base64Decode, decodeLen, output2, &outlen2);

    printf("\n\n decryption output:%s\tbase64 decoding output:%s\n", output2, base64Decode);
    printf("decryption length:%d\tbase64 decoding length:%d\n", outlen2, decodeLen);

    printf("Original text:%s\n", output2);
}

