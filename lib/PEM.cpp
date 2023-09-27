//
// Created by ling on 23-9-27.
//

#include "PEM.h"
#include "PemException.h"

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
            return std::shared_ptr<PemData>(new PemData(pCert));
        }
    }
} // ling