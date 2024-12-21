#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdint> 

void displayBanner() {
    const std::string NEON_BLUE = "\033[1;94m";
    const std::string RESET_COLOR = "\033[0m";

    std::cout << NEON_BLUE <<
" ______   __  __   ______   ______   ______   __     __       ______  __  __   __   __   ______    \n"
"/\\  == \\ /\\ \\/\\ \\ /\\  == \\ /\\  == \\ /\\  __ \\ /\\ \\  _ \\ \\     /\\  ___\\/\\ \\/\\ \\ /\\ \"-.\\ \\ /\\  ___\\   \n"
"\\ \\  __< \\ \\ \\_\\ \\\\ \\  __< \\ \\  __< \\ \\ \\/\\ \\\\ \\ \\/ \".\\ \\    \\ \\  __\\\\ \\ \\_\\ \\\\ \\ \\-.  \\\\ \\ \\____  \n"
" \\ \\_____\\\\ \\_____\\\\ \\_\\ \\_\\\\ \\_\\ \\_\\\\ \\_____\\\\ \\__/\".~\\_\\    \\ \\_\\   \\ \\_____\\\\ \\_\\\"\\_\\\\ \\_____\\ \n"
"  \\/_____/ \\/_____/ \\/_/ /_/ \\/_/ /_/ \\/_____/ \\/_/   \\/_/     \\/_/    \\/_____/ \\/_/ \\/_/ \\/_____/ \n"
"                                                                                                   \n"
    << RESET_COLOR;
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss(hex.substr(i, 2));
        ss >> std::hex >> byte;
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

std::vector<uint8_t> readFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) throw std::runtime_error("Unable to open file");

    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void writeFile(const std::string& filePath, const std::vector<uint8_t>& data) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) throw std::runtime_error("Unable to create file");

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::vector<uint8_t> xorEncryptDecrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

int main() {
    const std::string NEON_GREEN = "\033[1;92m";
    const std::string NEON_YELLOW = "\033[1;93m";
    const std::string NEON_PINK = "\033[1;95m";
    const std::string RESET_COLOR = "\033[0m";

    try {
        displayBanner();

        std::string hexKey;
        std::cout << NEON_GREEN << "Enter your key (hex): " << RESET_COLOR;
        std::getline(std::cin, hexKey);

        hexKey.erase(std::remove_if(hexKey.begin(), hexKey.end(), [](char c) { return !std::isxdigit(c); }), hexKey.end());
        auto key = hexToBytes(hexKey);

        std::string imagePath;
        std::cout << NEON_GREEN << "Enter the path to the image you want to encrypt: " << RESET_COLOR;
        std::getline(std::cin, imagePath);

        auto imageData = readFile(imagePath);
        auto encryptedData = xorEncryptDecrypt(imageData, key);

        std::string outputPath;
        std::cout << NEON_GREEN << "Enter the output path for the encrypted/decrypted image (including filename): " << RESET_COLOR;
        std::getline(std::cin, outputPath);

        writeFile(outputPath, encryptedData);

        std::cout << NEON_YELLOW << "Image encrypted/decrypted and saved successfully!" << RESET_COLOR << std::endl;
    } catch (const std::exception& e) {
        std::cerr << NEON_PINK << "Error: " << e.what() << RESET_COLOR << std::endl;
        return 1;
    }

    return 0;
}
