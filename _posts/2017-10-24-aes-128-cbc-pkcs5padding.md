---
title: aes-128-cbc-pkcs5padding(openssl)
date: 2017-10-24 15:18:57
categories:
- 网络安全
tags:
- AES
- OpenSSL
---

基于OpenSSL 1.1.0g版本的AES128/CBC/PKCS5padding实现。

{% highlight c linenos %}
#include <string.h>

#include <openssl/aes.h>

#include <openssl/bio.h>

static int pkcs5_padding(const char *from, unsigned int from_len, char *to)
{
    unsigned int to_len = 0;
    unsigned int padding_len = 0;

    if (from == NULL || to == NULL || from_len == 0) {
        return -1;
    }

    to_len = (from_len / 16 + 1) * 16;
    padding_len = to_len - from_len;

    memcpy(to, from, from_len);
    memset(to + from_len, padding_len, padding_len);

    return 0;
}

static int pkcs5_unpadding(const char *from, unsigned int from_len, char *to)
{
    unsigned int padding_len = 0;

    if (from == NULL || to == NULL || from_len == 0 || from_len % 16 != 0) {
        return -1;
    }

    padding_len = from[from_len -1];
    if (padding_len > 16 || padding_len != from[from_len - padding_len]) {
        return -2;
    }

    memcpy(to, from, from_len - padding_len);

    return 0;
}

int aes128_cbc_pkcs5padding_encrypt(const char *plain_text, unsigned int plain_text_len,
                                    const char *key, unsigned int key_len,
                                    char **cipher_text, unsigned int *cipher_text_len
                                   )
{
    int ret = 1;
    AES_KEY aes_key;
    unsigned char iv[16];
    char *plain_text_padding = NULL;
    int plain_text_padding_len = 0;

    if (plain_text == NULL || plain_text_len == 0 || key == NULL || key_len != 16 || cipher_text == NULL || cipher_text_len == NULL) {
        return -1;
    }
    plain_text_padding_len = (plain_text_len / 16 + 1) * 16;
    plain_text_padding = (char *)malloc(plain_text_padding_len);
    if (plain_text_padding == NULL) {
        goto err;
    }
    if (pkcs5_padding(plain_text, plain_text_len, plain_text_padding) != 0) {
        goto err;
    }

    memset(iv, 0, 16);

    AES_set_encrypt_key(key, 16 * 8, &aes_key);

    *cipher_text = (char *)malloc(plain_text_padding_len);
    if (*cipher_text == NULL) {
        goto err;
    }

    AES_cbc_encrypt(plain_text_padding, *cipher_text, plain_text_padding_len, &aes_key, iv, AES_ENCRYPT);
    *cipher_text_len = plain_text_padding_len;

    ret = 0;
err:
    free(plain_text_padding);
    plain_text_padding = NULL;
    return ret;
}

int aes128_cbc_pkcs5padding_decrypt(const char *cipher_text, unsigned int cipher_text_len,
                                    const char *key, unsigned int key_len,
                                    char **plain_text, unsigned int *plain_text_len
                                   )
{
    int ret = 1;
    AES_KEY aes_key;
    unsigned char iv[16];
    char *plain_text_padding = NULL;
    int plain_text_padding_len = 0;

    if (cipher_text == NULL || cipher_text_len == 0 || cipher_text_len % 16 != 0 ||
        key == NULL || key_len != 16 || plain_text == NULL || plain_text_len == NULL) {
        return -1;
    }

    plain_text_padding = (char *)malloc(cipher_text_len);
    if (plain_text_padding == NULL) {
        goto err;
    }

    memset(iv, 0, 16);
    AES_set_decrypt_key(key, 16 * 8, &aes_key);
    AES_cbc_encrypt(cipher_text, plain_text_padding, cipher_text_len, &aes_key, iv, AES_DECRYPT);

    *plain_text = (char *)malloc(cipher_text_len - plain_text_padding[cipher_text_len - 1]);
    if (*plain_text == NULL) {
        goto err;
    }

    if (pkcs5_unpadding(plain_text_padding, cipher_text_len, *plain_text) != 0) {
        free(*plain_text);
        *plain_text = NULL;
        goto err;
    }

    *plain_text_len = cipher_text_len - plain_text_padding[cipher_text_len -1];

    ret = 0;

err:
    free(plain_text_padding);
    plain_text_padding = NULL;
    return ret;
}

int main()
{
    int ret = 1;
    unsigned char key[16] = {0xd4, 0x6f, 0x8b, 0x75, 0x39, 0x5d, 0x67, 0x1d,
                             0xdc, 0xff, 0xc1, 0x09, 0xc8, 0x34, 0x57, 0x2b};
    char *plain_text_original =
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890"
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890";
    unsigned int plain_text_original_len = 1500;
    unsigned char *plain_text = NULL;
    unsigned int plain_text_len = 0;
    unsigned char *cipher_text = NULL;
    unsigned int cipher_text_len = 0;

    ret = aes128_cbc_pkcs5padding_encrypt(plain_text_original, plain_text_original_len, key, 16, &cipher_text, &cipher_text_len);
    if (ret != 0) {
        printf("encrypt error\n");
        goto err;
    } else {
        printf("encrypt success, the plain text in hex is:\n");
        BIO_dump_fp(stdout, plain_text_original, plain_text_original_len);
        printf("the cipher text in hex is:\n");
        BIO_dump_fp(stdout, cipher_text, cipher_text_len);
    }

    ret = aes128_cbc_pkcs5padding_decrypt(cipher_text, cipher_text_len, key, 16, &plain_text, &plain_text_len);
    if (ret != 0) {
        printf("decrypt error\n");
        goto err;
    } else {
        printf("decrypt success, the plain text in hex is:\n");
        BIO_dump_fp(stdout, plain_text, plain_text_len);
    }

    ret = 0;

err:
    free(plain_text);
    plain_text = NULL;
    free(cipher_text);
    cipher_text = NULL;
    return ret;
}
{% endhighlight %}
