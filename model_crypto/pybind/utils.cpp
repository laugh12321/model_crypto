#include "mac.h"
#include <pybind11/pybind11.h>


PYBIND11_MODULE(utils, m) {
    m.doc() = "Python bindings for utility functions within model_crypto";

    m.def("GetMACAddress", &GetMACAddress, "Get the MAC address");
}
