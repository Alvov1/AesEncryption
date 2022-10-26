#ifndef AESENCRYPTION_ENCRYPTION_H
#define AESENCRYPTION_ENCRYPTION_H

#include <filesystem>

void encryptFile(const std::filesystem::path& location, const std::string& key, const std::string& salt) {
    if(!std::filesystem::exists(location))
        throw std::invalid_argument("File is not found.");
    if(!std::filesystem::is_regular_file(location))
        throw std::runtime_error("Filesystem object is not a regular file.");

}

#endif //AESENCRYPTION_ENCRYPTION_H
