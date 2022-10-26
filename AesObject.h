#ifndef BACKEND_AESOBJECT_H
#define BACKEND_AESOBJECT_H

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <array>
#include <openssl/evp.h>

#include "Exceptions.h"

class AesObject final {
    std::string plaintext;
    std::basic_string<unsigned char> ciphertext;

    using KeyArray = std::array<unsigned char, 32>;
    using IvArray = std::array<unsigned char, 16>;
    AesObject(std::string plaintext_, const std::string& salt_, const KeyArray& key_, const IvArray & iv_);
    AesObject(std::basic_string<unsigned char> ciphertext_, const std::string& salt_, const KeyArray& key_, const IvArray& iv_);

    static IvArray generateIV(const KeyArray& key) {
        static constexpr auto a = 57, b = 129, c = 77;

        if(key.empty())
            throw EncryptionException("Aes encryption: Trying to generate initialization vector based on empty key.");

        IvArray iv{};
        for(unsigned short counter = 0, i = 0; i < 16; ++i, counter = (counter + c) % key.size())
            iv[i] = static_cast<char>((a * static_cast<unsigned>(key[counter]) + b) % 256);
        return iv;
    }
    static std::pair<KeyArray, IvArray> prepareKeyIV(const std::string& key, const std::string& iv);
public:
    /* Encrypt plain text. */
    static AesObject fromPlain(std::string plaintext, const std::string& salt, const std::string& key, const std::string& iv);
    static inline AesObject fromPlain(std::string plaintext, const std::string& salt, const KeyArray& key, const IvArray& iv) {
        return { std::move(plaintext), salt, key, iv };
    }

    /* Decrypt encrypted text. */
    static AesObject fromCipher(std::basic_string<unsigned char> ciphertext, const std::string& salt, const std::string& key, const std::string& iv);
    static inline AesObject fromCipher(std::basic_string<unsigned char> ciphertext, const std::string& salt, const KeyArray& key, const IvArray& iv) {
        return { std::move(ciphertext), salt, key, iv };
    };

    /* Generate IV based on key. Use carefully.  */
    static inline AesObject fromPlain(std::string plaintext, const std::string& salt, const KeyArray& key) {
        return AesObject::fromPlain(std::move(plaintext), salt, key, generateIV(key));
    }
    static inline AesObject fromCipher(std::basic_string<unsigned char> ciphertext, const std::string& salt, const KeyArray& key) {
        return AesObject::fromCipher(std::move(ciphertext), salt, key, generateIV(key));
    }

    AesObject() = delete;
    AesObject(const AesObject& copy) = delete;
    AesObject& operator=(const AesObject& assign) = delete;
    AesObject(AesObject&& move) = delete;
    AesObject& operator=(AesObject&& assign_move) = delete;

    inline explicit operator std::string() const { return plaintext; }
    inline std::string getPlaintext() const { return plaintext; }
    inline explicit operator std::basic_string<unsigned char>() const { return ciphertext; }
    inline std::basic_string<unsigned char> getCiphertext() const { return ciphertext; }
    std::string getCiphertextBase64() const;
    friend std::ostream& operator<<(std::ostream& stream, const AesObject& object);
};


#endif //BACKEND_AESOBJECT_H
