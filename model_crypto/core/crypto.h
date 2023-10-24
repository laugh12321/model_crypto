#pragma once

#include <string>
#include <iostream>

#include <cryptopp/hex.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>

namespace Crypto {
    const size_t MAGIC_NUMBER_LEN = 3;
    const size_t VERSION_NUMBER_LEN = 3;
    const size_t KEY_HASH_LENGTH_LEN = 3;

    // Function to calculate SHA256 hash of a key
    std::string CalculateSHA256(const CryptoPP::SecByteBlock& key);

    std::string ConvertToString(const size_t& value, const size_t& length);

    // Function to verify if the key matches the stored hash
    bool VerifyKey(const CryptoPP::SecByteBlock& key, const std::string& storedKeyHash);

    // Encrypt function with header information
    std::string EncryptWithHeader(const std::string& data, const std::string& keyStr, const std::string& ivStr, const std::string& magicNumber, const std::string& version);

    // Decrypt function for header-aware encrypted data
    std::string DecryptWithHeader(const std::string& cipher, const std::string& keyStr, const std::string& ivStr);

    std::string GenerateAESKey(const std::string& content);

    std::string GenerateRandomIV();
}
