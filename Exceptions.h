#ifndef BACKEND_EXCEPTIONS_H
#define BACKEND_EXCEPTIONS_H

#include <exception>
#include <openssl/err.h>

class EncryptionException final: public std::exception {
    std::string message;
public:
    explicit EncryptionException(const std::string& message)
    : message(std::move("Encryption exception. " + message + " function failed: ")) {
        while(unsigned long errCode = ERR_get_error())
            this->message += ERR_error_string(errCode, nullptr);
    }
    const char* what() noexcept {
        return message.c_str();
    }
};

class OssLibraryException final: public std::exception {
    std::string message;
public:
    explicit OssLibraryException(std::string message): message(std::move(message)) {}
    const char* what() noexcept { return message.c_str(); }
};

#endif //BACKEND_EXCEPTIONS_H
