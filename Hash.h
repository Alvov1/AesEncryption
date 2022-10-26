#ifndef BACKEND_HASH_H
#define BACKEND_HASH_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>

#include "Exceptions.h"

namespace sha256 {
    inline std::string hash(const std::string &plainText) {
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        if (context == nullptr)
            throw OssLibraryException("EVP_MD_CTX_new");

        if (0 == EVP_DigestInit_ex(context, EVP_sha256(), nullptr))
            throw OssLibraryException("EVP_DigestInit_ex");

        if (0 == EVP_DigestUpdate(context, plainText.c_str(), plainText.size()))
            throw OssLibraryException("EVP_DigestUpdate");

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned length = 0;
        if (0 == EVP_DigestFinal_ex(context, hash, &length))
            throw OssLibraryException("EVP_DigestFinal_ex");
        EVP_MD_CTX_free(context);

        std::stringstream ss;
        for (unsigned int i = 0; i < length; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        return ss.str();
    }
}

#endif //BACKEND_HASH_H
