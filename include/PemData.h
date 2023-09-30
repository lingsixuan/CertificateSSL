//
// Created by ling on 23-9-27.
//

#ifndef CERTIFICATESSL_PEMDATA_H
#define CERTIFICATESSL_PEMDATA_H

#include <openssl/x509v3.h>
#include <string>
#include <openssl/pem.h>
#include "RSATool.h"

namespace ling {
    /**
     * 证书数据
     */
    class PemData : public RSATool {
    private:

    protected:
        explicit PemData(X509 *pCert,EVP_PKEY *pri = nullptr);

    public:
        friend class PEM;

        ~PemData() override;
    };

} // ling

#endif //CERTIFICATESSL_PEMDATA_H
