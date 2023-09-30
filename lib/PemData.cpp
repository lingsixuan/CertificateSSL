//
// Created by ling on 23-9-27.
//

#include <iostream>
#include "PemData.h"
#include "RSATool.h"

namespace ling {
    PemData::PemData(X509 *pCert, EVP_PKEY *pri) : RSATool() {
        EVP_PKEY *public_key = X509_get_pubkey(pCert);
        if (EVP_PKEY_type(EVP_PKEY_id(public_key)) != EVP_PKEY_RSA) {
            // 不是 RSA 密钥对，无法转换
            std::cout << "不是RSA密钥对" << std::endl;
        }
        setKey(public_key, pri);
    }

    PemData::~PemData() {

    }
} // ling