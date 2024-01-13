//
// Created by ling on 2023/3/2.
//

#ifndef OPENSSL_RSATOOL_H
#define OPENSSL_RSATOOL_H

#include <mutex>
#include "openssl/rsa.h"


class RSATool {
private:
    RSA *key = nullptr;
    char *pub = nullptr;
    char *pri = nullptr;
    std::mutex mutex;

protected:
    void init();

    explicit RSATool();

    void setKey(const EVP_PKEY *pub, const EVP_PKEY *pri = nullptr);

public:
    RSATool(const char *公钥, const char *私钥);

    explicit RSATool(int keySize);

    explicit RSATool(const EVP_PKEY *pub, const EVP_PKEY *pri = nullptr);

    virtual ~RSATool();

    const char *getPublicKey();

    const char *getPrivateKey();

    int getKeyBitSize();

    int lockPublicKey(int size, const unsigned char *in, unsigned char *out);

    int unlockPublicKey(int size, const unsigned char *in, unsigned char *out);

    int lockPrivateKey(int size, const unsigned char *in, unsigned char *out);

    int unlockPrivateKey(int size, const unsigned char *in, unsigned char *out);

};


#endif //OPENSSL_RSATOOL_H
