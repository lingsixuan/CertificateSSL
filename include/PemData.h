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
        EVP_PKEY *pri;
        EVP_PKEY *public_key;
        std::string subject;
        std::string issuer;
        time_t startTime, endTime;

        static time_t ASN1_to_Unix(ASN1_TIME *asn1);

    protected:
        explicit PemData(X509 *pCert, EVP_PKEY *pri = nullptr);

        void setPri(EVP_PKEY *pri);

        void initKey();

    public:
        friend class PEM;

        ~PemData() override;

        [[nodiscard]] const std::string &getSubject() const;

        [[nodiscard]] const std::string &getIssuer() const;

        [[nodiscard]] time_t getStartTime() const;

        [[nodiscard]] time_t getEndTime() const;
    };

} // ling

#endif //CERTIFICATESSL_PEMDATA_H
