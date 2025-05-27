#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <map>
#include <queue>
#include <vector>
#include <sstream>
#include <iomanip>
#include <array>

// ————— Huffman structures —————

struct Node {
    unsigned char byte;
    size_t freq;
    Node *l, *r;
    Node(unsigned char b, size_t f) : byte(b), freq(f), l(nullptr), r(nullptr) {} 
}; 

struct NodeCmp {
    bool operator()(Node* a, Node* b) const { return a->freq > b->freq; } 
};

using CodeMap = std::array<std::string, 256>; 
                                              
void buildCodes(Node* root, CodeMap& codes, std::string prefix = "") {
    if (!root) return;
    if (!root->l && !root->r) {
        codes[static_cast<size_t>(root->byte)] = prefix; 
    } else {
        buildCodes(root->l, codes, prefix + '0');
        buildCodes(root->r, codes, prefix + '1');
    }
}

Node* buildTree(const std::vector<unsigned char>& data) {
    std::map<unsigned char, size_t> freq; 
    for (auto b : data) freq[b]++;       
    std::priority_queue<Node*, std::vector<Node*>, NodeCmp> pq; 
    for (auto& kv : freq)
        pq.push(new Node(kv.first, kv.second));

    while (pq.size() > 1) { 
        Node* a = pq.top(); pq.pop(); 
        Node* b = pq.top(); pq.pop();
        Node* parent = new Node(0, a->freq + b->freq);
        parent->l = a; parent->r = b; 
        pq.push(parent); 
    }
    return pq.empty() ? nullptr : pq.top(); 

}

void freeTree(Node* root) {
    if (!root) return;
    freeTree(root->l);
    freeTree(root->r);
    delete root;
}

std::string huffmanCompress(const std::string& raw) {
    std::vector<unsigned char> data(raw.begin(), raw.end());
    Node* root = buildTree(data);
    if (!root) return "";

    CodeMap codes;
    buildCodes(root, codes);

    std::string outBits;
    outBits.reserve(data.size() * 8); 
    for (auto b : data)
        outBits += codes[static_cast<size_t>(b)]; 
    freeTree(root);
    return outBits;
}

// ————— SHA‑256 helpers —————

void sha256_raw(const std::string& msg, unsigned char out[SHA256_DIGEST_LENGTH]) { 
    SHA256(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), out);
}

std::string to_hex(const unsigned char* buf, size_t len) { 
    std::ostringstream oss; 
    oss << std::hex << std::setfill('0'); 
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<int>(buf[i]);
    return oss.str();
}

// ————— RSA helpers —————

RSA* generateRSAKey() {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new(); 
    BN_set_word(e, RSA_F4); 
    if (RSA_generate_key_ex(rsa, 2048, e, nullptr) != 1) { 
        unsigned long err = ERR_get_error();
        char buf[120];
        ERR_error_string(err, buf);
        std::cerr << "RSA key gen error: " << buf << "\n";
        RSA_free(rsa);
        rsa = nullptr;
    }
    BN_free(e);
    return rsa;
}

std::string signData(RSA* rsa, const std::string& msg) {
    unsigned char hash[SHA256_DIGEST_LENGTH]; // buffer to store hash
    sha256_raw(msg, hash); // hashing takes place

    std::vector<unsigned char> sig(RSA_size(rsa));
    unsigned int sigLen = 0;
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH,sig.data(), &sigLen, rsa) != 1) {
        unsigned long err = ERR_get_error();
        char buf[120];
        ERR_error_string(err, buf);
        std::cerr << "RSA_sign error: " << buf << "\n";
        return {};
    }
    return std::string(reinterpret_cast<char*>(sig.data()), sigLen); 
}

// ————— Main —————

int main() {
    std::string message;
    std::cout << "Enter your message"<<"\n";
    std::getline(std::cin, message);
    std::cout << "\nOriginal Message: " << message << "\n";
    RSA* key = generateRSAKey();
    if (!key) return 1;

    std::string rawSig = signData(key, message);
    std::string hexSig = to_hex(
        reinterpret_cast<const unsigned char*>(rawSig.data()), rawSig.size());
    size_t hexSigSize = hexSig.size()*4;
    std::cout << "\nOriginal Signature (hex): " << hexSig << "\n";
    std::cout << "Hexadecimal Signature Length: " << hexSigSize << " bits\n";

    std::string compressed = huffmanCompress(rawSig);
    std::cout<<"Compressed signature ---"<<"\n";
    std::cout << compressed<<"\n";
    std::cout << "Compressed signature bit‐string length: " << compressed.size() << "\n";

    RSA_free(key);
    return 0;
}
