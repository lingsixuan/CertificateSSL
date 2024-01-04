//
// Created by ling on 23-9-27.
//

#include <iostream>
#include "PemData.h"
#include "RSATool.h"
#include "PemException.h"

namespace ling {
    PemData::PemData(X509 *pCert, EVP_PKEY *pri) : RSATool() {
        EVP_PKEY *public_key = X509_get_pubkey(pCert);
        if (EVP_PKEY_type(EVP_PKEY_id(public_key)) != EVP_PKEY_RSA) {
            // 不是 RSA 密钥对，无法转换
            throw PemException("不是RSA密钥对");
        }
        this->public_key = public_key;
        this->pri = pri;

        X509_NAME *subject = X509_get_subject_name(pCert);
        char subject_name[256];
        X509_NAME_oneline(subject, subject_name, sizeof(subject_name));
        this->subject = subject_name;

        // 获取证书颁发者信息
        X509_NAME *issuer = X509_get_issuer_name(pCert);
        char issuer_name[256];
        X509_NAME_oneline(issuer, issuer_name, sizeof(issuer_name));
        this->issuer = issuer_name;

        // 获取证书有效期
        ASN1_TIME *not_before = X509_get_notBefore(pCert);
        ASN1_TIME *not_after = X509_get_notAfter(pCert);
        //printf("证书有效期: %s 到 %s\n", not_before->data, not_after->data);
        this->startTime = ASN1_to_Unix(not_before);
        this->endTime = ASN1_to_Unix(not_after);
    }

    PemData::~PemData() {

    }

    void PemData::setPri(EVP_PKEY *pri) {
        this->pri = pri;
    }

    void PemData::initKey() {
        setKey(public_key, pri);
    }

    time_t PemData::ASN1_to_Unix(ASN1_TIME *asn1) {
        // 自定义ASN1_TIME_to_unix函数
        struct tm timeinfo{};
        memset(&timeinfo, 0, sizeof(struct tm));

        const char *str = (const char *) asn1->data;
        size_t len = asn1->length;

        // 检查ASN.1时间字符串的长度，根据不同的格式进行解析
        if (len == 13) {
            // "YYMMDDHHMMSSZ" 格式
            if (sscanf(str, "%2d%2d%2d%2d%2d%2dZ",
                       &timeinfo.tm_year, &timeinfo.tm_mon, &timeinfo.tm_mday,
                       &timeinfo.tm_hour, &timeinfo.tm_min, &timeinfo.tm_sec) == 6) {
                timeinfo.tm_year += 100; // 将年份调整为从 1900 开始
                timeinfo.tm_mon -= 1;    // 月份从 0 开始
            }
        } else if (len == 15) {
            // "YYYYMMDDHHMMSSZ" 格式
            if (sscanf(str, "%4d%2d%2d%2d%2d%2dZ",
                       &timeinfo.tm_year, &timeinfo.tm_mon, &timeinfo.tm_mday,
                       &timeinfo.tm_hour, &timeinfo.tm_min, &timeinfo.tm_sec) == 6) {
                timeinfo.tm_year -= 1900; // 年份已经是四位数
                timeinfo.tm_mon -= 1;     // 月份从 0 开始
            }
        } else {
            return -1;
        }

        // 将 struct tm 转换为 Unix 时间戳
        time_t unixTime = mktime(&timeinfo);
        if (unixTime == -1) {
            return -1;
        }

        return unixTime;
    }

    const std::string &PemData::getSubject() const {
        return this->subject;
    }

    const std::string &PemData::getIssuer() const {
        return this->issuer;
    }

    time_t PemData::getStartTime() const {
        return this->startTime;
    }

    time_t PemData::getEndTime() const {
        return this->endTime;
    }


} // ling