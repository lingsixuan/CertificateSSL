//
// Created by ling on 23-9-27.
//

#ifndef CERTIFICATESSL_PEMDATA_H
#define CERTIFICATESSL_PEMDATA_H

#include <openssl/x509v3.h>
#include <string>
#include <openssl/pem.h>

namespace ling {
    /**
     * 证书数据
     */
    class PemData {
    private:
        //证书结构体，保存用户证书
        X509 *pCert = nullptr;
    protected:
        explicit PemData(X509 *pCert);

    public:
        friend class PEM;

        virtual ~PemData();
    };

} // ling

#endif //CERTIFICATESSL_PEMDATA_H
