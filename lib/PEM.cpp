//
// Created by ling on 23-9-27.
//

#include <iostream>
#include "PEM.h"
#include "PemException.h"
#include <openssl/err.h>
#include <atomic>

namespace ling {
    PEM::PEM(const std::string &rootPemPath) {
        BIO *pbio = nullptr;
        //读取CA根证书
        pbio = BIO_new_file(rootPemPath.c_str(), "r");
        try {
            this->init(pbio);
        } catch (const std::runtime_error &e) {
            BIO_free(pbio);
            throw e;
        }
        BIO_free(pbio);
    }

    /*PEM::PEM(const std::string &rootPemPath, const std::string &priPath, const char *password) : PEM(rootPemPath) {
        FILE *fp = fopen(priPath.c_str(), "r");
        if (fp == nullptr) {
            throw PemException("私钥无法访问");
        }
        EVP_PKEY *privateKey = nullptr;
        privateKey = PEM_read_PrivateKey(fp, nullptr, [](char *buf, int size, int rwflag, void *u) -> int {
            if (u == nullptr)
                return 0;
            int pass_size = strlen((const char *) u);
            if (pass_size > size) {
                pass_size = size;
            }
            memcpy(buf, (const void *) u, pass_size);
            return pass_size;
        }, (void *) password);
        fclose(fp);
        if (privateKey == nullptr) {
            throw PemException("私钥损坏！");
        }
        pri = privateKey;
    }*/

    PEM::PEM(const char *ptr, size_t size) {
        BIO *pbio = nullptr;
        //读取CA根证书
        pbio = BIO_new_mem_buf(ptr, size);
        try {
            this->init(pbio);
        } catch (const std::runtime_error &e) {
            BIO_free(pbio);
            throw e;
        }
        BIO_free(pbio);
    }

    PEM::~PEM() {
        X509_free(pCaCert);
        X509_free(pCaCert);
        X509_STORE_free(pCaCertStore);
    }

    void PEM::init(BIO *bio) {
        pCaCert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (pCaCert == nullptr) {
            X509_free(pCaCert);
            throw PemException("读取根证书失败！");
        }
        pCaCertStore = X509_STORE_new();
        //设置检查CRL标志位，如果设置此标志位，则检查CRL，否则不检查CRL。
        //X509_STORE_set_flags(pCaCertStore, X509_V_FLAG_CRL_CHECK);
        X509_STORE_add_cert(pCaCertStore, pCaCert);      //添加根证书到证书存储区
        //X509_STORE_add_crl(pCaCertStore, Crl);           //添加CRL到证书存储区
    }

    std::shared_ptr<PemData> PEM::verifyUserPem(const std::string &pemPath) {
        BIO *pbio = nullptr;
        pbio = BIO_new_file(pemPath.c_str(), "r");
        std::shared_ptr<PemData> temp;
        try {
            temp = verifyUserPem(pbio);
        } catch (const std::runtime_error &e) {
            BIO_free(pbio);
            throw e;
        }
        temp->initKey();
        BIO_free(pbio);
        return temp;
    }

    std::shared_ptr<PemData> PEM::verifyUserPem(const char *ptr, size_t size) {
        BIO *pbio = nullptr;
        //读取CA根证书
        pbio = BIO_new_mem_buf(ptr, size);
        std::shared_ptr<PemData> temp;
        try {
            temp = verifyUserPem(pbio);
        } catch (const std::runtime_error &e) {
            BIO_free(pbio);
            throw e;
        }
        temp->initKey();
        BIO_free(pbio);
        return temp;
    }

    std::shared_ptr<PemData> PEM::verifyUserPem(BIO *bio) {
        X509 *pCert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (pCert == nullptr) {
            X509_free(pCert);
            throw PemException("读取用户证书出错");
        }

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();                             //创建证书存储区上下文环境

        //初始化证书存储区上下文环境（ctx)，设置根证书(pCaCertStore),待验证的证书(pCert)，CA证书链(CertStack)
        STACK_OF(X509) *CertStack = nullptr;
        int ret = X509_STORE_CTX_init(ctx, pCaCertStore, pCert, CertStack);
        if (ret != 1) {
            X509_free(pCert);
            X509_STORE_CTX_cleanup(ctx);
            X509_STORE_CTX_free(ctx);
            throw PemException("初始化ctx失败");
        }
        //验证用户证书，返回1表示验证成功，返回0表示验证失败
        ret = X509_verify_cert(ctx);
        if (ret != 1) {
            X509_free(pCert);
            X509_STORE_CTX_cleanup(ctx);
            X509_STORE_CTX_free(ctx);
            throw PemException("证书验证失败！");
        } else {
            X509_STORE_CTX_cleanup(ctx);
            X509_STORE_CTX_free(ctx);
            auto temp = std::shared_ptr<PemData>(new PemData(pCert));
            X509_free(pCert);
            return temp;
        }
    }

    PEM::PrivatePemLockEnum PEM::isPrivatePemLock(const std::string &path) {
        // 从私钥文件中读取私钥
        EVP_PKEY *privateKey = nullptr;
        FILE *privateKeyFile = fopen(path.c_str(), "r");

        if (privateKeyFile == nullptr) {
            std::cout << "无法打开私钥文件" << std::endl;
            // 处理错误情况
            return PrivatePemLockEnum::openError;
        } else {
            std::atomic<bool> flag = false;

            privateKey = PEM_read_PrivateKey(privateKeyFile, nullptr, [](char *buf, int size, int rwflag, void *u) -> int {
                ((std::atomic<bool> *) u)->store(true);
                return 0;
            }, &flag);
            fclose(privateKeyFile);

            if (flag.load()) {
                return PrivatePemLockEnum::lock;
            }

            if (privateKey == nullptr) {
                // 判断私钥是否被加密
                return PrivatePemLockEnum::error;
            } else {
                EVP_PKEY_free(privateKey);
                return PrivatePemLockEnum::unlock;
            }
        }
    }

    std::shared_ptr<PemData> PEM::verifyUserPem(const std::string &pemPath, const std::string &priKeyPath, const char *password) {
        BIO *pbio = nullptr;
        pbio = BIO_new_file(pemPath.c_str(), "r");
        std::shared_ptr<PemData> temp;
        try {
            temp = verifyUserPem(pbio);
        } catch (const std::runtime_error &e) {
            BIO_free(pbio);
            throw e;
        }

        FILE *fp = fopen(priKeyPath.c_str(), "r");
        if (fp == nullptr) {
            throw PemException("私钥无法访问");
        }
        EVP_PKEY *privateKey = nullptr;

        privateKey = PEM_read_PrivateKey(fp, nullptr, [](char *buf, int size, int rwflag, void *u) -> int {
            if (u == nullptr) {
                return 0;
            }
            int pass_size = strlen((const char *) u);
            if (pass_size > size) {
                pass_size = size;
            }
            memcpy(buf, (const void *) u, pass_size);
            return pass_size;
        }, (void *) password);

        fclose(fp);
        if (privateKey == nullptr) {
            throw PemException("私钥损坏！");
        }

        temp->setPri(privateKey);
        temp->initKey();
        EVP_PKEY_free(privateKey);

        BIO_free(pbio);
        return temp;
    }

    // 函数用于解析主题字段中的各个字段
    std::unordered_map<std::string, std::string> PEM::ParseSubject(const std::string& subject) {
        std::unordered_map<std::string,std::string> map;

        // 使用 '/' 作为分隔符将主题字段拆分为不同的字段
        size_t pos = 0;
        while (pos < subject.length()) {
            size_t end = subject.find('/', pos);
            if (end == std::string::npos) {
                end = subject.length();
            }

            std::string field = subject.substr(pos, end - pos);

            // 将字段分为键值对，以 '=' 分隔
            size_t equalPos = field.find('=');
            if (equalPos != std::string::npos) {
                std::string key = field.substr(0, equalPos);
                std::string value = field.substr(equalPos + 1);
                map[key] = value;
            }

            pos = end + 1; // 移动到下一个字段的起始位置
        }

        return map;
    }

} // ling