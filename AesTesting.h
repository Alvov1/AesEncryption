#ifndef BACKEND_AESTESTING_H
#define BACKEND_AESTESTING_H

#include <random>
#include "AesObject.h"

void startTesting() {
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0,255); // distribution in range [1, 6]

    const std::string salt("I am very unique salt value");

    for(unsigned i = 0; i < 10'000; ++i) {
        const auto size = dist(rng);
        std::string message(size, 0);
        for(unsigned short j = 0; j < size; ++j)
            message[j] = static_cast<char>(dist(rng));

        std::array<unsigned char, 32> key{};
        for(unsigned short j = 0; j < 32; ++j)
            key[j] = static_cast<unsigned char>(dist(rng));

        std::array<unsigned char, 16> iv{};
        for(unsigned short j = 0; j < 16; ++j)
            iv[j] = static_cast<unsigned char>(dist(rng));

        try {
            const auto object = AesObject::fromPlain(message, salt, key, iv);
            const auto cipherText = object.getCiphertext();
            const auto cipherObject = AesObject::fromCipher(cipherText, salt, key, iv);
            const auto text = cipherObject.getPlaintext();

            if(text != message)
                throw std::runtime_error("Wrong decoding: " + text);

        } catch (const std::exception& e) {
            std::cerr << "Failed for: " << message << ", key:";
            for(const auto& value: key)
                std::cerr  << " " << static_cast<unsigned short>(value);
            std::cerr << ", iv: ";
            for(const auto& value: iv)
                std::cerr << " " << static_cast<unsigned short>(value);
            std::cerr << ". What: " << e.what() << std::endl;
            continue;
        }
//        std::cout << "Ok" << std::endl;
    }
}

#endif //BACKEND_AESTESTING_H
