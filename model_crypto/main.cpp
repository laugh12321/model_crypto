#include "mac.h"
#include "crypto.h"
#include <iostream>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;


bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}


std::string fileRead(const std::string& filename) {
    std::ifstream ifs(filename, std::ios::in | std::ios::binary | std::ios::ate);

    if (!ifs) {
        std::cerr << "Error opening file for reading: " << filename << std::endl;
        exit(1);
    }

    std::ifstream::pos_type fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::string fileContent(fileSize, '\0');
    ifs.read(&fileContent[0], fileSize);
    ifs.close();

    return fileContent;
}


void fileWrite(const std::string& filename, const std::string& data) {
    std::ofstream ofs(filename, std::ios::out | std::ios::binary | std::ios::trunc);

    if (!ofs) {
        std::cerr << "Error opening file for writing: " << filename << std::endl;
        exit(1);
    }

    ofs.write(data.c_str(), data.size());
    ofs.close();
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <operation> [args...]" << std::endl;
        std::cout << "Available operations:" << std::endl;
        std::cout << "1. generate <keydir>" << std::endl;
        std::cout << "2. encrypt <file> <keydir> <output> [additional <modelname> <version>]" << std::endl;
        std::cout << "3. decrypt <file> <keydir> <output>" << std::endl;
        return 1;
    }

    std::string operation = argv[1];

    if (operation == "generate") {
        if (argc != 3) {
            std::cout << "Usage: " << argv[0] << " generate <keydir>" << std::endl;
            return 1;
        }

        std::string keydir = argv[2];
        fs::path keydirPath(keydir);

        if (!fs::exists(keydirPath)) {
            std::cerr << "Error: Key directory does not exist." << std::endl;
            return 1;
        }

        std::string macAddress = GetMACAddress();
        std::string macKey = Crypto::GenerateAESKey(macAddress);
        std::string ivStr = Crypto::GenerateRandomIV();
        fs::path macKeyFile = keydirPath / "key.txt";
        fs::path ivStrFile = keydirPath / "iv.txt";
        fileWrite(macKeyFile.string(), macKey);
        fileWrite(ivStrFile.string(), ivStr);
    } else if (operation == "encrypt" || operation == "decrypt") {
        if (argc < 5 || argc > 7) {
            std::cout << "Usage: " << argv[0] << " " << operation << " <file> <keydir> <output> [additional <modelname> <version>]" << std::endl;
            return 1;
        }

        std::string file = argv[2];
        std::string keydir = argv[3];
        std::string output = argv[4];
        fs::path filePath(file);
        fs::path keydirPath(keydir);
        fs::path outputDir(output);

        if (!fs::exists(filePath)) {
            std::cerr << "Error: Input file does not exist." << std::endl;
            return 1;
        }

        if (!fs::exists(keydirPath)) {
            std::cerr << "Error: Key directory does not exist." << std::endl;
            return 1;
        }

        fs::path macKeyFile = keydirPath / "key.txt";
        fs::path ivStrFile = keydirPath / "iv.txt";
        std::string key = fileRead(macKeyFile.string());
        std::string iv = fileRead(ivStrFile.string());

        std::string additionalArg1 = (argc > 5) ? argv[5] : "MODEL";
        std::string additionalArg2 = (argc > 6) ? argv[6] : "VERSION:1.0";
        fs::path outputFilePath = outputDir / (operation + "_" + filePath.filename().string());
        std::string filedata = fileRead(filePath.string());

        if (operation == "encrypt") {
            std::string outdata = Crypto::EncryptWithHeader(filedata, key, iv, additionalArg1, additionalArg2);
            fileWrite(outputFilePath.string(), outdata);
        } else {
            std::string outdata = Crypto::DecryptWithHeader(filedata, key, iv);
            fileWrite(outputFilePath.string(), outdata);
        }
    } else {
        std::cout << "Invalid operation. Available operations: generate, encrypt, decrypt" << std::endl;
        return 1;
    }

    return 0;
}
