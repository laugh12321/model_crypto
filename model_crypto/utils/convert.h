#pragma once

#include <string>
#include <vector>

std::vector<unsigned char> Convert2TRTengine(const std::string& data) {
    // Allocate a vector with the same size as the input data
    std::vector<unsigned char> engine(data.begin(), data.end());

    return engine;
}
