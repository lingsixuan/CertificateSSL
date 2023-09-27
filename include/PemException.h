//
// Created by ling on 23-9-27.
//

#ifndef CERTIFICATESSL_PEMEXCEPTION_H
#define CERTIFICATESSL_PEMEXCEPTION_H


#include <stdexcept>

namespace ling {

    class PemException : public std::runtime_error {
    public:
        explicit PemException(const std::string &arg) : runtime_error(arg) {

        }

        explicit PemException(const char *unnamed) : runtime_error(unnamed) {

        }

        explicit PemException(runtime_error &&unnamed) : runtime_error(unnamed) {

        }

        explicit PemException(const runtime_error &unnamed) : runtime_error(unnamed) {

        }
    };
}


#endif //CERTIFICATESSL_PEMEXCEPTION_H
