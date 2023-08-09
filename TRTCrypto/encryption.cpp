#include "encryption.h"


// Function to calculate SHA256 hash of a key
std::string TRTCrypto::CalculateSHA256(const CryptoPP::SecByteBlock &key) {
    CryptoPP::SHA256 hash;
    std::string hashResult;

    CryptoPP::StringSource calculate(key.data(), key.size(), true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hashResult)
            )
        )
    );

    return hashResult;
}

std::string TRTCrypto::Convert2String(const size_t &value, const size_t &length) {
    // Convert size_t to string
    std::stringstream ss;
    ss << value;
    std::string result = ss.str();

    // Left-pad the string with spaces to ensure the length is 3 characters
    if (result.length() < length) {
        result = std::string(length - result.length(), ' ') + result;
    }

    return result;
}


// Function to verify if the key matches the stored hash
bool TRTCrypto::VerifyKey(const CryptoPP::SecByteBlock &key, const std::string &storedKeyHash) {
    std::string calculatedKeyHash = CalculateSHA256(key);
    return calculatedKeyHash == storedKeyHash;
}


// Encrypt function with header information
std::string TRTCrypto::EncryptWithHeader(const std::string &data, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv, const std::string &magicNumber, const std::string &version) {
    // Header format: [magic_number_len | magic_number | version_len | version | key_hash_length | key_hash | encrypted_data]

    std::string cipher;

    try {
        CryptoPP::GCM<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Calculate SHA256 hash of the key
        std::string keyHash = CalculateSHA256(key);

        // Get the length
        const size_t magicNumberLength = magicNumber.length();
        const size_t versionLength = version.length();
        const size_t keyHashLength = keyHash.length();

        // Construct the header
        std::string header = Convert2String(magicNumberLength, MAGIC_NUMBER_LEN) + \
            magicNumber + Convert2String(versionLength, VERSION_NUMBER_LEN) + version + \
            Convert2String(keyHashLength, KEY_HASH_LENGTH_LEN) + keyHash;

        // Encrypt the data
        CryptoPP::StringSource s(data, true, 
            new CryptoPP::AuthenticatedEncryptionFilter(e,
                new CryptoPP::StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource

        // Prepend the header to the cipher
        cipher = header + cipher;
    } catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return cipher;
}

// Decrypt function for header-aware encrypted data
std::string TRTCrypto::DecryptWithHeader(const std::string &cipher, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv) {
    // Header format: [magic_number_len | magic_number | version_len | version | key_hash_length | key_hash | encrypted_data]

    std::string recovered;

    try {
        CryptoPP::GCM<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Extract header information
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

        // Verify the key using stored hash
        if (!VerifyKey(key, keyHash)) {
            std::cerr << "Key verification failed." << std::endl;
            exit(1);
        }

        // Decrypt the data
        // The StreamTransformationFilter removes
        //  padding as required.
        CryptoPP::StringSource(encryptedData, true, 
            new CryptoPP::AuthenticatedDecryptionFilter(d,
                new CryptoPP::StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource
    } catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return recovered;
}

std::vector<unsigned char> TRTCrypto::Convert2TRTengine(const std::string& data) {
    unsigned char* engine_data[1];
    engine_data[0] = new unsigned char[data.length() + 1];
    std::copy(data.begin(), data.end(), engine_data[0]);
    engine_data[0][data.length()] = '\0';

    // Convert char* array to vector<char>
    std::vector<unsigned char> engine(engine_data[0], engine_data[0] + data.length());
    // Clean up the memory
    delete* engine_data;
    return engine;
}

std::string TRTCrypto::GenerateAESKey(const std::string& macAddress) {
    CryptoPP::byte hash[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256().CalculateDigest(hash, reinterpret_cast<const CryptoPP::byte*>(macAddress.c_str()), macAddress.length());

    CryptoPP::HexEncoder encoder;
    std::string encodedHash;
    encoder.Attach(new CryptoPP::StringSink(encodedHash));
    encoder.Put(hash, sizeof(hash));
    encoder.MessageEnd();

    return encodedHash.substr(0, 32); // AES-256 key length is 32 bytes
}

std::string TRTCrypto::GenerateRandomIV() {
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

CryptoPP::SecByteBlock TRTCrypto::StringToSecByteBlock(const std::string &str) {
    return CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte *>(str.data()), str.size());
}