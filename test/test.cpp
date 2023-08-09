#include "util.h"
#include "encryption.h"


int main() {
    std::string filename = "ori.txt";
    std::string encrypted = "enc.txt";
    std::string decrypted = "dec.txt";

    std::string macAddress = GetMACAddress();
    std::string macKey = TRTCrypto::GenerateAESKey(macAddress);
    std::string ivStr = TRTCrypto::GenerateRandomIV();

    CryptoPP::SecByteBlock key = TRTCrypto::StringToSecByteBlock(macKey);
    CryptoPP::SecByteBlock iv = TRTCrypto::StringToSecByteBlock(ivStr);

    fileWrite("macKey.txt", macKey);
    fileWrite("ivStr.txt", ivStr);

    std::string oridata = fileRead(filename);

    std::string cipher = TRTCrypto::EncryptWithHeader(oridata, key, iv, "TRTENGINE", "VERSION:1.10");
    fileWrite(encrypted, cipher);

    std::string recovered = TRTCrypto::DecryptWithHeader(cipher, key, iv);
    fileWrite(decrypted, recovered);

    std::cout << "Original data: " << oridata << std::endl;
    return 0;
}