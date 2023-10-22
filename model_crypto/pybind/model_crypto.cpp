#include "crypto.h"
#include <pybind11/pybind11.h>

namespace py = pybind11;

PYBIND11_MODULE(model_crypto, m) {
    m.doc() = "Model Crypto Module";

    m.def("EncryptWithHeader", [](const std::string& data, const std::string& key, const std::string& iv, const std::string& magicNumber, const std::string& version) -> py::bytes {
        std::string result = Crypto::EncryptWithHeader(data, key, iv, magicNumber, version);
        return py::bytes(result);
    }, "Encrypt data with header");

    m.def("DecryptWithHeader", [](const std::string& cipher, const std::string& key, const std::string& iv) -> py::bytes {
        std::string result = Crypto::DecryptWithHeader(cipher, key, iv);
        return py::bytes(result);
    }, "Decrypt data with header");

    m.def("GenerateAESKey", &Crypto::GenerateAESKey, "Generate AES key from content");

    m.def("GenerateRandomIV", &Crypto::GenerateRandomIV, "Generate a random IV");
}
