//
// Created by ling on 23-9-27.
//

#include "PemData.h"

namespace ling {
    PemData::PemData(X509 *pCert) {

    }

    PemData::~PemData() {
        X509_free(this->pCert);
    }
} // ling