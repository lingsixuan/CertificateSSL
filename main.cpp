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
        auto pem = ling::PEM(argv[2]);
        pem.verifyUserPem(argv[1]);
        pem.verifyUserPem(argv[1]);
        std::cout << "验证成功！" << std::endl;
    } catch (const std::runtime_error &e) {
        std::cout << e.what() << std::endl;
    }
}
