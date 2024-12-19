#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <cstring>
#include <limits>
#include <sstream>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>
#include <oqs/oqs.h>

// Secure memory management class: Implements RAII and secure cleanup
class SecureBuffer {
private:
    std::unique_ptr<uint8_t[]> data;
    size_t size;

public:
    explicit SecureBuffer(size_t length) :
        data(std::make_unique<uint8_t[]>(length)),
        size(length) {
        if (!data) {
            throw std::bad_alloc();
        }
        memset(data.get(), 0, size);  // Zero-initialize: Avoids leaking sensitive data
    }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept :
        data(std::move(other.data)),
        size(other.size) {
        other.size = 0;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            if (data) {
                OQS_MEM_cleanse(data.get(), size); // Securely erase data: Before reassignment
            }
            data = std::move(other.data);
            size = other.size;
            other.size = 0;
        }
        return *this;
    }

    uint8_t* get() { return data.get(); }
    const uint8_t* get() const { return data.get(); }
    size_t getSize() const { return size; }

    ~SecureBuffer() {
        if (data) {
            OQS_MEM_cleanse(data.get(), size); // Securely erase data: During destruction
        }
    }
};

class PostQuantumCrypto {
private:
    static constexpr const char* ALGORITHM = "Kyber1024";
    SecureBuffer publicKey;
    SecureBuffer privateKey;
    OQS_KEM* method;
    std::map<std::string, std::vector<uint8_t>> contactPublicKeys;

public:
    PostQuantumCrypto() :
        publicKey(OQS_KEM_kyber_1024_length_public_key),
        privateKey(OQS_KEM_kyber_1024_length_secret_key),
        method(nullptr) {
        method = OQS_KEM_new(ALGORITHM);
        if (method == nullptr) {
            throw std::runtime_error("Failed to initialize KEM algorithm");
        }
        if (OQS_KEM_keypair(method, publicKey.get(), privateKey.get()) != OQS_SUCCESS) {
            OQS_KEM_free(method);
            throw std::runtime_error("Key pair generation failed");
        }
    }

    ~PostQuantumCrypto() {
        if (method) {
            OQS_KEM_free(method);  // Secure cleanup of KEM method
            method = nullptr;
        }
    }

    PostQuantumCrypto(const PostQuantumCrypto&) = delete;
    PostQuantumCrypto& operator=(const PostQuantumCrypto&) = delete;
    PostQuantumCrypto(PostQuantumCrypto&& other) noexcept = default;
    PostQuantumCrypto& operator=(PostQuantumCrypto&& other) noexcept = default;

    std::vector<uint8_t> getPublicKey() const {
        return std::vector<uint8_t>(publicKey.get(),
                                  publicKey.get() + method->length_public_key);
    }

    void addContactPublicKey(const std::string& name, const std::vector<uint8_t>& key) {
        if (key.size() != method->length_public_key) {
            throw std::runtime_error("Invalid public key length");
        }
        contactPublicKeys[name] = key;
    }

    std::vector<std::string> listContacts() const {
        std::vector<std::string> contacts;
        for (const auto& pair : contactPublicKeys) {
            contacts.push_back(pair.first);
        }
        return contacts;
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encrypt(const std::string& contactName) {
        if (!method) throw std::runtime_error("KEM not initialized");

        auto it = contactPublicKeys.find(contactName);
        if (it == contactPublicKeys.end()) {
            throw std::runtime_error("Contact not found");
        }

        SecureBuffer cipherText(method->length_ciphertext);
        SecureBuffer sharedSecret(method->length_shared_secret);

        if (OQS_KEM_encaps(method, cipherText.get(), sharedSecret.get(),
            it->second.data()) != OQS_SUCCESS) {
            throw std::runtime_error("Encapsulation failed");
        }

        return {
            std::vector<uint8_t>(cipherText.get(),
                                cipherText.get() + cipherText.getSize()),
            std::vector<uint8_t>(sharedSecret.get(),
                                sharedSecret.get() + sharedSecret.getSize())
        };
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipherText) {
        if (!method) throw std::runtime_error("KEM not initialized");

        SecureBuffer sharedSecret(method->length_shared_secret);

        if (OQS_KEM_decaps(method, sharedSecret.get(), cipherText.data(),
            privateKey.get()) != OQS_SUCCESS) {
            throw std::runtime_error("Decapsulation failed");
        }

        return std::vector<uint8_t>(sharedSecret.get(),
                                  sharedSecret.get() + sharedSecret.getSize());
    }
};

void displayBanner() {
    const std::string NEON_BLUE = "\033[1;94m";
    const std::string RESET_COLOR = "\033[0m";

    std::cout << NEON_BLUE <<
" ______   __  __   ______   ______   ______   __     __    \n"
"/\\  == \\ /\\ \\/\\ \\ /\\  == \\ /\\  == \\ /\\  __ \\ /\\ \\  _ \\ \\   \n"
"\\ \\  __< \\ \\ \\_\\ \\\\ \\  __< \\ \\  __< \\ \\ \\/\\ \\\\ \\ \\/ \".\\ \\  \n"
" \\ \\_____\\\\ \\_____\\\\ \\_\\ \\_\\\\ \\_\\ \\_\\\\ \\_____\\\\ \\__/\".~\\_\\ \n"
"  \\/_____/ \\/_____/ \\/_/ /_/ \\/_/ /_/ \\/_____/ \\/_/   \\/_/ \n"
"                                        \n"
    << RESET_COLOR;
}

void displayDateTime() {
    const std::string NEON_PINK = "\033[1;95m";
    const std::string RESET_COLOR = "\033[0m";

    std::time_t now = std::time(nullptr);
    const char* username = std::getenv("USER");

    std::cout << NEON_PINK
              << "Current Date and Time (UTC): "
              << std::put_time(std::gmtime(&now), "%Y-%m-%d %H:%M:%S")
              << std::endl;

    if (username) {
        std::cout << "Current User's Login: " << username << std::endl;
    }
    std::cout << RESET_COLOR;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    if (hex.empty() || hex.length() % 2 != 0) {
        throw std::runtime_error("Invalid hex string");
    }

    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss(hex.substr(i, 2));
        ss >> std::hex >> byte;
        bytes.push_back(static_cast<uint8_t>(byte));
    }

    return bytes;
}

int main() {
    const std::string NEON_YELLOW = "\033[1;93m";
    const std::string NEON_PINK = "\033[1;95m";
    const std::string RESET_COLOR = "\033[0m";

    try {
        OQS_init();
        displayBanner();
        displayDateTime();
        PostQuantumCrypto crypto;

        while (true) {
            std::cout << "\nPost-Quantum Cryptography Tool (Burrow)\n";
            std::cout << NEON_YELLOW;
            std::cout << "1. Show My Public Key\n";
            std::cout << "2. Add Contact's Public Key\n";
            std::cout << "3. List Contacts\n";
            std::cout << "4. Generate Shared Secret for Contact\n";
            std::cout << "5. Decrypt Received Secret\n";
            std::cout << "6. Exit\n";
            std::cout << "Choose option: ";
            std::cout << RESET_COLOR;

            int choice;
            if (!(std::cin >> choice)) {
                std::cin.clear();
                std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
                std::cout << NEON_PINK << "Invalid input. Please enter a number.\n"
                         << RESET_COLOR;
                continue;
            }
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

            try {
                switch (choice) {
                    case 1: {
                        auto myPublicKey = crypto.getPublicKey();
                        std::cout << NEON_PINK << "\nYour Public Key (Hex): "
                                 << bytesToHex(myPublicKey) << RESET_COLOR << std::endl;
                        break;
                    }
                    case 2: {
                        std::string contactName, hexPublicKey;
                        std::cout << NEON_PINK << "Enter contact name: ";
                        std::getline(std::cin, contactName);
                        std::cout << "Enter contact's public key (hex): ";
                        std::getline(std::cin, hexPublicKey);

                        hexPublicKey.erase(
                            std::remove_if(hexPublicKey.begin(), hexPublicKey.end(),
                                         [](char c) { return !std::isxdigit(c); }),
                            hexPublicKey.end());

                        auto contactKey = hexToBytes(hexPublicKey);
                        crypto.addContactPublicKey(contactName, contactKey);
                        std::cout << "Contact added successfully!" << RESET_COLOR << std::endl;
                        break;
                    }
                    case 3: {
                        auto contacts = crypto.listContacts();
                        std::cout << NEON_PINK << "\nStored Contacts:\n";
                        if (contacts.empty()) {
                            std::cout << "No contacts found.\n";
                        } else {
                            for (const auto& contact : contacts) {
                                std::cout << "- " << contact << "\n";
                            }
                        }
                        std::cout << RESET_COLOR;
                        break;
                    }
                    case 4: {
                        std::string contactName;
                        std::cout << NEON_PINK << "Enter contact name: ";
                        std::getline(std::cin, contactName);

                        auto [cipherText, sharedSecret] = crypto.encrypt(contactName);

                        std::cout << "\nGenerated Cipher Text (send this to contact): \n"
                                 << bytesToHex(cipherText)
                                 << "\n\nShared Secret (keep this private): \n"
                                 << bytesToHex(sharedSecret)
                                 << RESET_COLOR << std::endl;
                        break;
                    }
                    case 5: {
                        std::cout << NEON_PINK << "Enter received cipher text (hex): ";
                        std::string hexCipherText;
                        std::getline(std::cin, hexCipherText);

                        hexCipherText.erase(
                            std::remove_if(hexCipherText.begin(), hexCipherText.end(),
                                         [](char c) { return !std::isxdigit(c); }),
                            hexCipherText.end());

                        auto cipherText = hexToBytes(hexCipherText);
                        auto sharedSecret = crypto.decrypt(cipherText);

                        std::cout << "Decrypted Shared Secret: "
                                 << bytesToHex(sharedSecret)
                                 << RESET_COLOR << std::endl;
                        break;
                    }
                    case 6:
                        std::cout << NEON_PINK << "Exiting...\n" << RESET_COLOR;
                        OQS_destroy();
                        return 0;
                    default:
                        std::cout << NEON_PINK << "Invalid option. Please try again.\n"
                                 << RESET_COLOR;
                }
            }
            catch (const std::exception& e) {
                std::cerr << NEON_PINK << "Operation failed: " << e.what() << std::endl
                         << RESET_COLOR;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << NEON_PINK << "Fatal error: " << e.what() << std::endl
                 << RESET_COLOR;
        OQS_destroy();
        return 1;
    }

    OQS_destroy();
    return 0;
}