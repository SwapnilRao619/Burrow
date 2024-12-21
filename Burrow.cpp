#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <ctime>
#include <cctype>
#include <algorithm>
#include <iomanip>
#include <limits>
#include <map>
#include <oqs/oqs.h>
#include <cstring>

// Secure memory management class: Implements RAII and secure cleanup
class SecureBuffer {
    std::unique_ptr<uint8_t[]> data;
    size_t size;

public:
    explicit SecureBuffer(size_t length) : data(std::make_unique<uint8_t[]>(length)), size(length) {
        if (!data) throw std::bad_alloc();
        memset(data.get(), 0, size);  // Zero-initialize: Avoids leaking sensitive data
    }

    SecureBuffer(SecureBuffer&& other) noexcept : data(std::move(other.data)), size(other.size) {
        other.size = 0;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            if (data) OQS_MEM_cleanse(data.get(), size); // Securely erase data: Before reassignment
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
        if (data) OQS_MEM_cleanse(data.get(), size); // Securely erase data: During destruction
    }
};

class PostQuantumCrypto {
    static constexpr const char* ALGORITHM = "Kyber1024";
    SecureBuffer publicKey, privateKey;
    OQS_KEM* method;
    std::map<std::string, std::vector<uint8_t>> contactPublicKeys;

public:
    PostQuantumCrypto() : publicKey(OQS_KEM_kyber_1024_length_public_key), privateKey(OQS_KEM_kyber_1024_length_secret_key), method(OQS_KEM_new(ALGORITHM)) {
        if (!method || OQS_KEM_keypair(method, publicKey.get(), privateKey.get()) != OQS_SUCCESS) throw std::runtime_error("Initialization failed");
    }

    ~PostQuantumCrypto() { if (method) OQS_KEM_free(method); }

    std::vector<uint8_t> getPublicKey() const { return { publicKey.get(), publicKey.get() + method->length_public_key }; }

    void addContactPublicKey(const std::string& name, const std::vector<uint8_t>& key) {
        if (key.size() != method->length_public_key) throw std::runtime_error("Invalid public key length");
        contactPublicKeys[name] = key;
    }

    void removeContactPublicKey(const std::string& name) {
        contactPublicKeys.erase(name);
    }

    std::vector<std::string> listContacts() const {
        std::vector<std::string> contacts;
        for (const auto& pair : contactPublicKeys) contacts.push_back(pair.first);
        return contacts;
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encrypt(const std::string& contactName) {
        auto it = contactPublicKeys.find(contactName);
        if (it == contactPublicKeys.end()) throw std::runtime_error("Contact not found");

        SecureBuffer cipherText(method->length_ciphertext), sharedSecret(method->length_shared_secret);
        if (OQS_KEM_encaps(method, cipherText.get(), sharedSecret.get(), it->second.data()) != OQS_SUCCESS) throw std::runtime_error("Encapsulation failed");

        return { {cipherText.get(), cipherText.get() + cipherText.getSize()}, {sharedSecret.get(), sharedSecret.get() + sharedSecret.getSize()} };
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipherText) {
        SecureBuffer sharedSecret(method->length_shared_secret);
        if (OQS_KEM_decaps(method, sharedSecret.get(), cipherText.data(), privateKey.get()) != OQS_SUCCESS) throw std::runtime_error("Decapsulation failed");
        return { sharedSecret.get(), sharedSecret.get() + sharedSecret.getSize() };
    }
};

void displayBanner() {
    const std::string NEON_BLUE = "\033[1;94m", RESET_COLOR = "\033[0m";
    std::cout << NEON_BLUE <<
" ______   __  __   ______   ______   ______   __     __    \n"
"/\\  == \\ /\\ \\/\\ \\ /\\  == \\ /\\  == \\ /\\  __ \\ /\\ \\  _ \\ \\   \n"
"\\ \\  __< \\ \\ \\_\\ \\\\ \\  __< \\ \\  __< \\ \\ \\/\\ \\\\ \\ \\/ \".\\ \\  \n"
" \\ \\_____\\\\ \\_____\\\\ \\_\\ \\_\\\\ \\_\\ \\_\\\\ \\_____\\\\ \\__/\".~\\_\\ \n"
"  \\/_____/ \\/_____/ \\/_/ /_/ \\/_/ /_/ \\/_____/ \\/_/   \\/_/ \n"
"                                        \n" << RESET_COLOR;
}

void displayDateTime() {
    const std::string NEON_PINK = "\033[1;95m", RESET_COLOR = "\033[0m";
    std::time_t now = std::time(nullptr);
    std::cout << NEON_PINK << "Current Date and Time (UTC): " << std::put_time(std::gmtime(&now), "%Y-%m-%d %H:%M:%S") << "\nCurrent User's Login: " << std::getenv("USER") << std::endl << RESET_COLOR;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : bytes) ss << std::setw(2) << static_cast<int>(byte);
    return ss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.empty() || hex.length() % 2 != 0) throw std::runtime_error("Invalid hex string");

    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss(hex.substr(i, 2));
        ss >> std::hex >> byte;
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

void runTests(PostQuantumCrypto& crypto) {
    const std::string NEON_GREEN = "\033[1;92m", NEON_RED = "\033[1;91m", RESET_COLOR = "\033[0m";

    std::cout << "Running test cases...\n";

    // Test Case 1: Generate and display public key
    std::cout << NEON_GREEN << "Test Case 1: Generate and display public key\n";
    auto myPublicKey = crypto.getPublicKey();
    std::cout << (myPublicKey.empty() ? (NEON_RED + std::string("FAIL\n")) : std::string("PASS\n")) << RESET_COLOR;

    // Test Case 2: Add and list a contact
    std::cout << NEON_GREEN << "Test Case 2: Add and list a contact\n";
    std::string contactName = "Bob";
    std::string hexPublicKey = bytesToHex(myPublicKey);
    try {
        crypto.addContactPublicKey(contactName, hexToBytes(hexPublicKey));
        auto contacts = crypto.listContacts();
        std::cout << (contacts.empty() || contacts[0] != contactName ? (NEON_RED + std::string("FAIL\n")) : std::string("PASS\n")) << RESET_COLOR;
        crypto.removeContactPublicKey(contactName); // Remove contact to avoid confusion
    } catch (...) {
        std::cout << NEON_RED << "FAIL\n" << RESET_COLOR;
    }

    // Test Case 3: Encrypt and decrypt a message
    std::cout << NEON_GREEN << "Test Case 3: Encrypt and decrypt a message\n";
    try {
        crypto.addContactPublicKey(contactName, hexToBytes(hexPublicKey));
        auto [cipherText, sharedSecret] = crypto.encrypt(contactName);
        auto decryptedSecret = crypto.decrypt(cipherText);
        std::cout << (sharedSecret != decryptedSecret ? (NEON_RED + std::string("FAIL\n")) : std::string("PASS\n")) << RESET_COLOR;
        crypto.removeContactPublicKey(contactName); // Remove contact to avoid confusion
    } catch (...) {
        std::cout << NEON_RED << "FAIL\n" << RESET_COLOR;
    }

    // Test Case 4: Attempt to decrypt invalid ciphertext
    std::cout << NEON_RED << "Test Case 4: Attempt to decrypt invalid ciphertext\n";
    std::string invalidCipherTextHex = "000102030405060708090a0b0c0d0e0f";
    try {
        crypto.decrypt(hexToBytes(invalidCipherTextHex));
        std::cout << "FAIL\n" << RESET_COLOR;
    } catch (...) {
        std::cout << NEON_GREEN << "PASS\n" << RESET_COLOR;
    }

    std::cout << "Loading the menu...\n";
}

int main() {
    const std::string NEON_YELLOW = "\033[1;93m", NEON_PINK = "\033[1;95m", RESET_COLOR = "\033[0m";

    try {
        OQS_init();
        displayBanner();
        displayDateTime();
        PostQuantumCrypto crypto;

        // Run tests
        runTests(crypto);

        while (true) {
            std::cout << "\nPost-Quantum Cryptography Tool (Burrow)\n" << NEON_YELLOW
                      << "1. Show My Public Key\n2. Add Contact's Public Key\n3. List Contacts\n4. Generate Shared Secret for Contact\n5. Decrypt Received Secret\n6. Exit\nChoose option: " << RESET_COLOR;

            int choice;
            if (!(std::cin >> choice)) {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::cout << NEON_PINK << "Invalid input. Please enter a number.\n" << RESET_COLOR;
                continue;
            }
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            try {
                switch (choice) {
                    case 1:
                        std::cout << NEON_PINK << "\nYour Public Key (Hex): " << bytesToHex(crypto.getPublicKey()) << RESET_COLOR << std::endl;
                        break;
                    case 2: {
                        std::string contactName, hexPublicKey;
                        std::cout << NEON_PINK << "Enter contact name: ";
                        std::getline(std::cin, contactName);
                        std::cout << "Enter contact's public key (hex): ";
                        std::getline(std::cin, hexPublicKey);

                        hexPublicKey.erase(std::remove_if(hexPublicKey.begin(), hexPublicKey.end(), [](char c) { return !std::isxdigit(c); }), hexPublicKey.end());
                        crypto.addContactPublicKey(contactName, hexToBytes(hexPublicKey));
                        std::cout << "Contact added successfully!" << RESET_COLOR << std::endl;
                        break;
                    }
                    case 3: {
                        auto contacts = crypto.listContacts();
                        std::cout << NEON_PINK << "\nStored Contacts:\n";
                        if (contacts.empty()) {
                            std::cout << "No contacts found.\n";
                        } else {
                            for (const auto& contact : contacts) std::cout << "- " << contact << "\n";
                        }
                        std::cout << RESET_COLOR;
                        break;
                    }
                    case 4: {
                        std::string contactName;
                        std::cout << NEON_PINK << "Enter contact name: ";
                        std::getline(std::cin, contactName);
                        auto [cipherText, sharedSecret] = crypto.encrypt(contactName);
                        std::cout << "\nGenerated Cipher Text (send this to contact): \n" << bytesToHex(cipherText) << RESET_COLOR << std::endl;
                        break;
                    }
                    case 5: {
                        std::cout << NEON_PINK << "Enter received cipher text (hex): ";
                        std::string hexCipherText;
                        std::getline(std::cin, hexCipherText);
                        hexCipherText.erase(std::remove_if(hexCipherText.begin(), hexCipherText.end(), [](char c) { return !std::isxdigit(c); }), hexCipherText.end());
                        auto sharedSecret = crypto.decrypt(hexToBytes(hexCipherText));
                        std::cout << "Decrypted Shared Secret: " << bytesToHex(sharedSecret) << RESET_COLOR << std::endl;
                        break;
                    }
                    case 6:
                        std::cout << NEON_PINK << "Exiting...\n" << RESET_COLOR;
                        OQS_destroy();
                        return 0;
                    default:
                        std::cout << NEON_PINK << "Invalid option. Please try again.\n" << RESET_COLOR;
                }
            } catch (const std::exception& e) {
                std::cerr << NEON_PINK << "Operation failed: " << e.what() << std::endl << RESET_COLOR;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << NEON_PINK << "Fatal error: " << e.what() << std::endl << RESET_COLOR;
        OQS_destroy();
        return 1;
    }

    OQS_destroy();
    return 0;
}
