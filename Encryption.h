#ifndef AESENCRYPTION_ENCRYPTION_H
#define AESENCRYPTION_ENCRYPTION_H

#include <filesystem>
#include <fstream>

#include "AesObject.h"

std::filesystem::path encryptFile(const std::filesystem::path& location, const std::string& salt, const std::string& key, const std::string& iv) {
    if(!std::filesystem::exists(location))
        throw std::invalid_argument("File is not found.");
    if(!std::filesystem::is_regular_file(location))
        throw std::runtime_error("Filesystem object is not a regular file.");

    const auto initialFilename = location.filename().string();
    const auto cypheredFilename = AesObject::fromPlain(initialFilename, salt, key, iv).getCiphertextBase64();

    std::filesystem::path newLocation(location);
    newLocation.replace_filename(cypheredFilename);

    std::cout << "Before: " << location << std::endl;
    std::cout << "After: " << newLocation << std::endl << std::endl;

    return newLocation;
}

#endif //AESENCRYPTION_ENCRYPTION_H
