#include "AesObject.h"

AesObject::AesObject(std::string plaintext_, const std::string& salt_, const KeyArray& key_, const IvArray& iv_)
: plaintext(std::move(plaintext_)) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if(ctx == nullptr)
            throw OssLibraryException("EVP_CIPHER_CTX_new");

        if(0 == EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            throw OssLibraryException("EVP_EncryptInit_ex");

        if(0 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, nullptr))
            throw OssLibraryException("EVP_CIPHER_CTX_ctrl");

        if(0 == EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv_.data()))
            throw OssLibraryException("EVP_EncryptInit_ex");

        int len = 0;
        if(0 == EVP_EncryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(salt_.c_str()), static_cast<int>(salt_.size())))
            throw OssLibraryException("EVP_EncryptUpdate");

        ciphertext = std::basic_string<unsigned char>(plaintext.size() + 16, 0);
        if(0 == EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), static_cast<int>(plaintext.size())))
            throw OssLibraryException("EVP_EncryptUpdate");

        if(0 == EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
            throw OssLibraryException("EVP_EncryptFinal_ex");

        if(0 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, reinterpret_cast<void*>(ciphertext.data() + plaintext.size())))
            throw OssLibraryException("EVP_CIPHER_CTX_ctrl");

        EVP_CIPHER_CTX_free(ctx);
}

AesObject::AesObject(std::basic_string<unsigned char> ciphertext_, const std::string& salt_, const KeyArray& key_, const IvArray& iv_)
: ciphertext(std::move(ciphertext_)) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(ctx == nullptr)
            throw OssLibraryException("EVP_CIPHER_CTX_new");

        if(0 == EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            throw OssLibraryException("EVP_DecryptInit_ex");

        if(0 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, nullptr))
            throw OssLibraryException("EVP_CIPHER_CTX_ctrl");

        if(0 == EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv_.data()))
            throw OssLibraryException("EVP_DecryptInit_ex");

        int len = 0;
        if(0 == EVP_DecryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(salt_.c_str()), static_cast<int>(salt_.size())))
            throw OssLibraryException("EVP_DecryptUpdate");

        plaintext = std::string(ciphertext.size() - 16, 0);
        if(0 == EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &len, ciphertext.data(), static_cast<int>(ciphertext.size() - 16)))
            throw OssLibraryException("EVP_DecryptUpdate");
        int plaintext_len = len;

        if(0 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<void*>(reinterpret_cast<const void*>(ciphertext.data() + ciphertext.size() - 16))))
            throw OssLibraryException("EVP_CIPHER_CTX_ctrl");

        if(0 == EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data() + len), &len))
            throw OssLibraryException("EVP_DecryptionFinal_ex");
        plaintext[plaintext_len + len] = 0;

        EVP_CIPHER_CTX_free(ctx);
}

AesObject AesObject::fromPlain(std::string plaintext, const std::string &salt, const std::string &key, const std::string &iv) {
    const auto[key_, iv_] = prepareKeyIV(key, iv);
    return {std::move(plaintext), salt, key_, iv_ };
}

AesObject AesObject::fromCipher(std::basic_string<unsigned char> ciphertext, const std::string &salt, const std::string &key, const std::string &iv) {
    const auto[key_, iv_] = prepareKeyIV(key, iv);
    return {std::move(ciphertext), salt, key_, iv_ };
}

std::pair<AesObject::KeyArray, AesObject::IvArray> AesObject::prepareKeyIV(const std::string &key, const std::string &iv) {
    KeyArray key_{};
    for(unsigned i = 0; i < (key.size() >= 32 ? 32 : key.size()); ++i)
        key_[i] = static_cast<unsigned char>(key[i]);
    for(unsigned i = key.size(); key.size() < 32; ++i)
        key_[i] = static_cast<unsigned char>(' ');

    IvArray iv_{};
    for(unsigned i = 0; i < (iv.size() >= 16 ? 16 : iv.size()); ++i)
        iv_[i] = static_cast<unsigned char>(iv[i]);
    for(unsigned short i = iv.size(); i < 16; ++i)
        iv_[i] = static_cast<unsigned char>(' ');

    return { key_, iv_ };
}

std::ostream &operator<<(std::ostream &stream, const AesObject &object) {
    stream << "Plain text: " << object.plaintext << std::endl;
    stream << "Cipher text: " << object.ciphertext.data() << std::endl;
    return stream;
}

std::string AesObject::getCiphertextBase64() const {
    std::stringstream stream;
    for(auto value: ciphertext)
        stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value);
    return stream.str();
}