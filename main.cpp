#include <iostream>
#include <iostream>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <PEM.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage : %s ca_crt user_crt crl_file\n", argv[0]);
        return 0;
    }
    OPENSSL_add_all_algorithms_noconf();
    try {
        auto pem = ling::PEM(argv[2],"/data/local/tmp/CA.pem","intmainvoid");
        auto rsa = pem.verifyUserPem(argv[1]);
        std::cout << "验证成功！" << std::endl;
    } catch (const std::runtime_error &e) {
        std::cout << e.what() << std::endl;
    }

    switch (ling::PEM::isPrivatePemLock("/data/local/tmp/CA.pem")) {

        case ling::PEM::lock:
            std::cout << "锁定" << std::endl;
            break;
        case ling::PEM::unlock:
            std::cout << "解锁" << std::endl;
            break;
        case ling::PEM::error:
            std::cout << "损坏" << std::endl;
            break;
        case ling::PEM::openError:
            std::cout << "权限不足" << std::endl;
            break;
    }
}
