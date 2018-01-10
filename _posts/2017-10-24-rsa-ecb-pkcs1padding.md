---
title: rsa-ecb-pkcs1padding(openssl)
date: 2017-10-24 15:18:57
categories:
- 网络安全
tags:
- RSA
- OpenSSL
---

基于OpenSSL 1.1.0g版本的RSA128/ECB/PKCS1padding实现。

{% highlight c linenos %}
#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

RSA *generate_rsa_key_128(void)
{
    RSA *rsa = NULL;
    char random_seed[16];
    BIGNUM *bn = NULL;

    if (RAND_bytes(random_seed, 16) <= 0) {
        goto err;
    }

    RAND_seed(random_seed, sizeof(random_seed));

    bn = BN_new();
    if (bn == NULL) {
        goto err;
    }

    if (!BN_set_word(bn, RSA_F4)) {
        goto err;
    }

    rsa = RSA_new();
    if (rsa == NULL) {
        goto err;
    }

    if (!RSA_generate_key_ex(rsa, 1024, bn, NULL)) {
        rsa = NULL;
        goto err;
    }

err:
    BN_free(bn);
    bn = NULL;
    return rsa;
}

int rsa_public_key_to_x509(const RSA *rsa, char **rsa_public_key_x509, unsigned int *rsa_public_key_x509_len)
{
    int ret = 0;

    if (rsa == NULL || rsa_public_key_x509 == NULL || rsa_public_key_x509_len == NULL) {
        goto err;
    }

    ret = i2d_RSA_PUBKEY(rsa, rsa_public_key_x509);
    *rsa_public_key_x509_len = ret;

err:
    return ret;
}

RSA *rsa_public_key_from_x509(char *rsa_public_key_x509, unsigned int rsa_public_key_x509_len)
{
    RSA *ret = NULL;
    char *p = NULL;

    if (rsa_public_key_x509 == NULL || rsa_public_key_x509_len == 0) {
        goto err;
    }

    // use p as a temporary variable is mandatory.
    p = rsa_public_key_x509;

    ret = d2i_RSA_PUBKEY(NULL, &p, rsa_public_key_x509_len);

err:
    return ret;
}

int rsa_public_encrypt_128_pkcs1padding(const char *plain_text, unsigned int plain_text_len, RSA *rsa,
                                    char **cipher_text, unsigned int *cipher_text_len)
{
    int ret = 1;

    if (plain_text == NULL || plain_text_len > 128 - RSA_PKCS1_PADDING_SIZE ||
        rsa == NULL || cipher_text == NULL || cipher_text_len == NULL) {
        return -1;
    }

    if (RSA_size(rsa) != 128) {
        return -1;
    }

    *cipher_text = (char *)malloc(128);
    if (*cipher_text == NULL) {
        goto err;
    }

    *cipher_text_len = RSA_public_encrypt(plain_text_len, plain_text, *cipher_text, rsa, RSA_PKCS1_PADDING);
    if (*cipher_text_len <= 0) {
        goto err;
    }

    ret = 0;

err:
    return ret;
}

int rsa_private_decrypt_128_pkcs1padding(const char *cipher_text, unsigned int cipher_text_len, RSA *rsa,
                                         char **plain_text, unsigned int *plain_text_len)
{
    int ret = 1;

    if (cipher_text == NULL || rsa == NULL || plain_text == NULL || plain_text_len == NULL) {
        return -1;
    }

    if (RSA_size(rsa) != 128) {
        return -1;
    }

    *plain_text = (char *)malloc(128);
    if (*plain_text == NULL) {
        goto err;
    }

    *plain_text_len = RSA_private_decrypt(cipher_text_len, cipher_text, *plain_text, rsa, RSA_PKCS1_PADDING);
    if (*plain_text_len <= 0) {
        goto err;
    }

    ret = 0;

err:
    return ret;
}

int main(void)
{
    int ret = 1;
    RSA *rsa = NULL;
    char *public_key_x509 = NULL;
    unsigned int public_key_x509_len = 0;

    RSA *rsa_cloud = NULL;
    char *message = "longshine is a good man!";
    unsigned int message_len = 24;
    char *plain_text = NULL;
    unsigned int plain_text_len = 0;
    char *cipher_text = NULL;
    unsigned int cipher_text_len = 0;

    rsa = generate_rsa_key_128();
    if (rsa == NULL) {
        printf("generate rsa key failed\n");
        goto err;
    } else {
        printf("generate rsa key success:\n");
        RSA_print_fp(stdout, rsa, 8);
    }

    ret = rsa_public_key_to_x509(rsa, &public_key_x509, &public_key_x509_len);
    if (ret <= 0) {
        printf("convert the rsa public key to x509 failed\n");
        goto err;
    } else {
        printf("convert the rsa public key to x509 success:\n");
        BIO_dump_fp(stdout, public_key_x509, public_key_x509_len);
    }

    rsa_cloud = rsa_public_key_from_x509(public_key_x509, public_key_x509_len);
    if (rsa_cloud == NULL) {
        printf("convert the rsa public key from x509 failed\n");
        goto err;
    } else {
        printf("convert the rsa public key from x509 success\n");
        RSA_print_fp(stdout, rsa_cloud, 8);
    }

    ret = rsa_public_encrypt_128_pkcs1padding(message, message_len, rsa_cloud, &cipher_text, &cipher_text_len);
    if (ret) {
        printf("rsa public encrypt on cloud failed\n");
        goto err;
    } else {
        printf("rsa public encrypt on cloud success\n");
        BIO_dump_fp(stdout, cipher_text, cipher_text_len);
    }

    ret = rsa_private_decrypt_128_pkcs1padding(cipher_text, cipher_text_len, rsa, &plain_text, &plain_text_len);
    if (ret) {
        printf("rsa private decrypt failed\n");
        goto err;
    } else {
        printf("rsa private decrypt success\n");
        BIO_dump_fp(stdout, plain_text, plain_text_len);
    }

err:
    free(plain_text);
    plain_text = NULL;
    free(cipher_text);
    cipher_text = NULL;
    RSA_free(rsa_cloud);
    rsa_cloud = NULL;
    free(public_key_x509);
    public_key_x509 = NULL;
    RSA_free(rsa);
    rsa = NULL;
    return ret;
}
{% endhighlight %}
