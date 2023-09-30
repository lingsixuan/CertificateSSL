//
// Created by ling on 2023/3/2.
//

#include <cstring>
#include <stdexcept>
#include <iostream>
#include <RSATool.h>
#include "openssl/pem.h"

RSATool::RSATool(const char *公钥, const char *私钥) {
    if (公钥 == nullptr && 私钥 == nullptr) {
        throw std::invalid_argument("公钥和私钥不能同时为空！");
    }
    if (公钥 != nullptr) {
        BIO *g = BIO_new_mem_buf(公钥, strlen(公钥));
        PEM_read_bio_RSAPublicKey(g, &key, nullptr, nullptr);
        BIO_free(g);
    }
    if (私钥 != nullptr) {
        BIO *s = BIO_new_mem_buf(私钥, strlen(私钥));
        PEM_read_bio_RSAPrivateKey(s, &key, nullptr, nullptr);
        BIO_free(s);
    }
    init();
}

RSATool::RSATool(const EVP_PKEY *pub, const EVP_PKEY *pri) : RSATool() {
    this->setKey(pub, pri);
}

RSATool::RSATool(int keySize) {
    key = RSA_generate_key(keySize, RSA_F4, nullptr, nullptr);
    init();
}

RSATool::~RSATool() {
    RSA_free(key);
    delete[] this->pri;
    delete[] this->pub;
}

void RSATool::init() {
    BIO *b = BIO_new(BIO_s_mem());
    BIO *p = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(b, key, nullptr, nullptr, RSA_size(key) * 8, nullptr, nullptr);
    PEM_write_bio_RSAPublicKey(p, key);
    //先分配一个巨大的内存
    char *temp = new char[RSA_size(key) * 8];
    memset(temp, 0, RSA_size(key) * 8);
    BIO_read(b, temp, RSA_size(key) * 8);
    this->pri = new char[strlen(temp) + 1];
    this->pri[strlen(temp)] = 0;
    memcpy(this->pri, temp, strlen(temp));
    memset(temp, 0, RSA_size(key) * 8);
    BIO_read(p, temp, RSA_size(key) * 8);
    this->pub = new char[strlen(temp) + 1];
    this->pub[strlen(temp)] = 0;
    memcpy(this->pub, temp, strlen(temp));
    delete[] temp;
    BIO_free(b);
    BIO_free(p);
}

const char *RSATool::getPublicKey() {
    return this->pub;
}

const char *RSATool::getPrivateKey() {
    return this->pri;
}

int RSATool::getKeyBitSize() {
    return RSA_size(this->key) * 8;
}

int RSATool::公钥加密(int size, const unsigned char *in, unsigned char *out) {
    std::unique_lock<std::mutex> lock(mutex);
    return RSA_public_encrypt(size, in, out, key, RSA_PKCS1_PADDING);
}

int RSATool::公钥解密(int size, const unsigned char *in, unsigned char *out) {
    std::unique_lock<std::mutex> lock(mutex);
    return RSA_public_decrypt(size, in, out, key, RSA_PKCS1_PADDING);
}

int RSATool::私钥加密(int size, const unsigned char *in, unsigned char *out) {
    std::unique_lock<std::mutex> lock(mutex);
    return RSA_private_encrypt(size, in, out, key, RSA_PKCS1_PADDING);
}

int RSATool::私钥解密(int size, const unsigned char *in, unsigned char *out) {
    std::unique_lock<std::mutex> lock(mutex);
    return RSA_private_decrypt(size, in, out, key, RSA_PKCS1_PADDING);
}

RSATool::RSATool() {

}

void RSATool::setKey(const EVP_PKEY *pub, const EVP_PKEY *pri) {
    if (pub == nullptr && pri == nullptr)
        throw std::invalid_argument("公钥和私钥不能同时为空！");
    if (pub != nullptr && EVP_PKEY_type(EVP_PKEY_id(pub)) != EVP_PKEY_RSA) {
        throw std::invalid_argument("公钥无效");
    }
    if (pri != nullptr && EVP_PKEY_type(EVP_PKEY_id(pri)) != EVP_PKEY_RSA) {
        throw std::invalid_argument("私钥无效");
    }
    if (pri == nullptr) {
        this->key = (RSA *) EVP_PKEY_get0_RSA(pub);
        this->init();
    } else if (pub == nullptr) {
        this->key = (RSA *) EVP_PKEY_get0_RSA(pri);
        this->init();
    } else {
        this->key = RSA_new();
        // 获取公钥的 EVP_PKEY* 对象中的 RSA 密钥对
        const rsa_st *rsa_public_key = EVP_PKEY_get0_RSA(pub);
        // 获取私钥的 EVP_PKEY* 对象中的 RSA 密钥对
        const rsa_st *rsa_private_key = EVP_PKEY_get0_RSA(pri);
        BIO *b = BIO_new(BIO_s_mem());
        BIO *p = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(b, rsa_private_key, nullptr, nullptr, RSA_size(rsa_private_key) * 8, nullptr, nullptr);
        PEM_write_bio_RSAPublicKey(p, rsa_public_key);

        PEM_read_bio_RSAPublicKey(p, &key, nullptr, nullptr);
        PEM_read_bio_RSAPrivateKey(b, &key, nullptr, nullptr);

        BIO_free(b);
        BIO_free(p);
        this->init();
    }
}

