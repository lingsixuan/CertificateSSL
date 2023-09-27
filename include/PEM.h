//
// Created by ling on 23-9-27.
//

#ifndef CERTIFICATESSL_PEM_H
#define CERTIFICATESSL_PEM_H

#include <openssl/x509v3.h>
#include <string>
#include <openssl/pem.h>
#include <PemData.h>
#include <memory>

namespace ling {
    /**
     * 证书验证类
     */
    class PEM {
    private:
        //根证书
        X509 *pCaCert = nullptr;
        //证书存储区
        X509_STORE *pCaCertStore = nullptr;
    protected:
        /**
         * @throw PemException              出错时
         */
        void init(BIO *bio);

    public:
        /**
         * @param rootPemPath               根证书路径
         * @throw PemException              出错时
         */
        explicit PEM(const std::string &rootPemPath);

        /**
         *
         * @param ptr                       内存中的根证书
         * @param size                      ptr长度
         * @throw PemException              出错时
         */
        PEM(const char *ptr, size_t size);

        virtual ~PEM();

        /**
         * 验证用户证书
         * @param pemPath                   用户证书路径
         * @return                          用户证书信息
         * @throw PemException               验证出错时
         */
        std::shared_ptr<PemData> verifyUserPem(const std::string &pemPath);

        /**
         * 验证用户证书
         * @param ptr                       内存中的证书
         * @param size                      指针长度
         * @return                          用户证书信息
         * @throw PemException              出错时
         */
        std::shared_ptr<PemData> verifyUserPem(const char *ptr, size_t size);

        /**
         * 验证用户证书
         * @param bio                       证书流
         * @return                          用户证书信息
         * @throw PemException              出错时
         */
        std::shared_ptr<PemData> verifyUserPem(BIO *bio);

    };

} // ling

#endif //CERTIFICATESSL_PEM_H
