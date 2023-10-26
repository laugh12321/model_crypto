#include "crypto.hpp"


// Function to calculate SHA256 hash of a key
std::string Crypto::CalculateSHA256(const CryptoPP::SecByteBlock& key) {
    CryptoPP::SHA256 hash;
    std::string hashResult;

    CryptoPP::StringSource calculate(key, key.size(), true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hashResult)
            )
        )
    );

    return hashResult;
}


std::string Crypto::ConvertToString(const size_t& value, const size_t& length) {
    // Convert size_t to string and pad with spaces if needed
    std::string result = std::to_string(value);
    if (result.length() < length) {
        result = std::string(length - result.length(), ' ') + result;
    }
    return result;
}


// Function to verify if the key matches the stored hash
bool Crypto::VerifyKey(const CryptoPP::SecByteBlock& key, const std::string& storedKeyHash) {
    std::string calculatedKeyHash = CalculateSHA256(key);
    return calculatedKeyHash == storedKeyHash;
}


// Encrypt function with header information
std::string Crypto::EncryptWithHeader(const std::string& data, const std::string& keyStr, const std::string& ivStr, const std::string& magicNumber, const std::string& version) {
    std::string cipher;

    try {
        CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(keyStr.data()), keyStr.size());
        CryptoPP::SecByteBlock iv(reinterpret_cast<const CryptoPP::byte *>(ivStr.data()), ivStr.size());
        CryptoPP::GCM<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());

        std::string keyHash = CalculateSHA256(key);

        const size_t magicNumberLength = magicNumber.length();
        const size_t versionLength = version.length();
        const size_t keyHashLength = keyHash.length();

        // Construct the header
        std::string header;
        header.reserve(MAGIC_NUMBER_LEN + VERSION_NUMBER_LEN + KEY_HASH_LENGTH_LEN);
        header += ConvertToString(magicNumberLength, MAGIC_NUMBER_LEN);
        header += magicNumber;
        header += ConvertToString(versionLength, VERSION_NUMBER_LEN);
        header += version;
        header += ConvertToString(keyHashLength, KEY_HASH_LENGTH_LEN);
        header += keyHash;

        // Encrypt the data
        CryptoPP::StringSource s(data, true,
            new CryptoPP::AuthenticatedEncryptionFilter(e,
                new CryptoPP::StringSink(cipher)
            )
        );

        // Prepend the header to the cipher
        cipher = header + cipher;
    } catch(const CryptoPP::Exception& e) {
        // Handle the exception gracefully, e.g., log an error message
        std::cerr << "Encryption error: " << e.what() << std::endl;
    }

    return cipher;
}


// Decrypt function for header-aware encrypted data
std::string Crypto::DecryptWithHeader(const std::string& cipher, const std::string& keyStr, const std::string& ivStr) {
    std::string recovered;

    try {
        CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte *>(keyStr.data()), keyStr.size());
        CryptoPP::SecByteBlock iv(reinterpret_cast<const CryptoPP::byte *>(ivStr.data()), ivStr.size());
        CryptoPP::GCM<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());

        std::string magicNumberLengthStr = cipher.substr(0, MAGIC_NUMBER_LEN);
        size_t magicNumberLength = std::stoull(magicNumberLengthStr);
        std::string magicNumber = cipher.substr(MAGIC_NUMBER_LEN, magicNumberLength);

        std::string versionLengthStr = cipher.substr(MAGIC_NUMBER_LEN + magicNumberLength, VERSION_NUMBER_LEN);
        size_t versionLength = std::stoull(versionLengthStr);
        std::string version = cipher.substr(MAGIC_NUMBER_LEN + magicNumberLength + VERSION_NUMBER_LEN, versionLength);

        std::string keyHashLengthStr = cipher.substr(MAGIC_NUMBER_LEN + magicNumberLength + VERSION_NUMBER_LEN + versionLength, KEY_HASH_LENGTH_LEN);
        size_t keyHashLength = std::stoull(keyHashLengthStr);
        std::string keyHash = cipher.substr(MAGIC_NUMBER_LEN + magicNumberLength + VERSION_NUMBER_LEN + versionLength + KEY_HASH_LENGTH_LEN, keyHashLength);

        std::string encryptedData = cipher.substr(MAGIC_NUMBER_LEN + magicNumberLength + VERSION_NUMBER_LEN + versionLength + KEY_HASH_LENGTH_LEN + keyHashLength);

        if (!VerifyKey(key, keyHash)) {
            std::cerr << "Key verification failed." << std::endl;
            return "";
        }

        CryptoPP::StringSource(encryptedData, true,
            new CryptoPP::AuthenticatedDecryptionFilter(d,
                new CryptoPP::StringSink(recovered)
            )
        );
    } catch(const CryptoPP::Exception& e) {
        // Handle the exception gracefully, e.g., log an error message
        std::cerr << "Decryption error: " << e.what() << std::endl;
    }

    return recovered;
}


std::string Crypto::GenerateAESKey(const std::string& content) {
    CryptoPP::byte hash[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256().CalculateDigest(hash, reinterpret_cast<const CryptoPP::byte*>(content.c_str()), content.length());

    CryptoPP::HexEncoder encoder;
    std::string encodedHash;
    encoder.Attach(new CryptoPP::StringSink(encodedHash));
    encoder.Put(hash, sizeof(hash));
    encoder.MessageEnd();

    return encodedHash.substr(0, 32); // AES-256 key length is 32 bytes
}


std::string Crypto::GenerateRandomIV() {
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, sizeof(iv));

    CryptoPP::HexEncoder encoder;
    std::string encodedIV;
    encoder.Attach(new CryptoPP::StringSink(encodedIV));
    encoder.Put(iv, sizeof(iv));
    encoder.MessageEnd();

    return encodedIV;
}
