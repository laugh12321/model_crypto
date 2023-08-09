#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#include <cryptopp/hex.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>


const static size_t MAGIC_NUMBER_LEN = 3;
const static size_t VERSION_NUMBER_LEN = 3;
const static size_t KEY_HASH_LENGTH_LEN = 3;


namespace TRTCrypto {
    // Function to calculate SHA256 hash of a key
    std::string CalculateSHA256(const CryptoPP::SecByteBlock &key);

    std::string Convert2String(const size_t &value, const size_t &length);


    // Function to verify if the key matches the stored hash
    bool VerifyKey(const CryptoPP::SecByteBlock &key, const std::string &storedKeyHash);


    // Encrypt function with header information
    std::string EncryptWithHeader(const std::string &data, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv, const std::string &magicNumber, const std::string &version);

    // Decrypt function for header-aware encrypted data
    std::string DecryptWithHeader(const std::string &cipher, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv);

    std::vector<unsigned char> Convert2TRTengine(const std::string& data);

    std::string GenerateAESKey(const std::string& macAddress);

    std::string GenerateRandomIV();

    CryptoPP::SecByteBlock StringToSecByteBlock(const std::string &str);
}


#endif // !ENCRYPTION_H