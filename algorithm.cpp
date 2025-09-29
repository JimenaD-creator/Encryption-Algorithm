#include <iostream>
#include <vector>
#include <iomanip>
#include <string>
#include <fstream>
#include <sstream>
using namespace std;

const int BLOCK_SIZE = 8; 
const int TOTAL_ROUNDS = 5;

string cleanHexString(const string& hexStr) {
    string cleaned;
    for (char c : hexStr) {
        if (isxdigit(static_cast<unsigned char>(c))) {
            cleaned += c;
        }
    }
    return cleaned;
}

bool hexStringToBytes(const string& hexStr, vector<unsigned char>& output) {
    string cleaned = cleanHexString(hexStr);
    if (cleaned.length() % 2 != 0) {
        cout << "Error: Invalid hexadecimal length (must be even)." << endl;
        return false;
    }
    
    output.clear();
    for (size_t i = 0; i < cleaned.length(); i += 2) {
        string byteStr = cleaned.substr(i, 2);
        try {
            int value = stoi(byteStr, nullptr, 16);
            output.push_back(static_cast<unsigned char>(value));
        } catch (...) {
            cout << "Error: Invalid hexadecimal found." << endl;
            return false;
        }
    }
    return true;
}

string bytesToHexString(const vector<unsigned char>& data) {
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char byte : data) {
        ss << setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

void printBlock(const vector<unsigned char>& block, const string& label){
    cout << label << ": ";
    for(auto b : block){
        cout << setw(2) << setfill('0') << hex << (int)b << " ";
    }
    cout << dec << endl;
}

unsigned char rotateLeft(unsigned char byte, int n){
    return (byte << n) | (byte >> (8-n));
}

unsigned char rotateRight(unsigned char byte, int n){
    return (byte >> n) | (byte << (8-n));
}

vector<unsigned char> generateSubkey(const string& key, int round){
    vector<unsigned char> subkey;
    for(int i = 0; i < BLOCK_SIZE; i++){
        subkey.push_back((round + key[i % key.size()] + i * i) % 256);
    }
    return subkey;
}

void confusion(vector<unsigned char> &block, const vector<unsigned char> &subkey, int round){
    for(int i = 0; i < block.size(); i++){
        int tmp = ((block[i] ^ subkey[i % subkey.size()]) + i * i + round * 7);
        block[i] = (tmp % 256 + 256) % 256;
    }
}

void difusion(vector<unsigned char> &block){
    for(int i = 0; i < block.size(); i++){
        block[i] = rotateLeft(block[i], i + 1);
    }

    for(int i = 1; i < block.size(); i++){
        block[i] ^= block[i - 1];
    }

    vector<unsigned char> temp(block.size());
    for (int i = 0; i < block.size(); i++){
        int j = (i % 2 == 0) ? (block.size() - 1 - i / 2) : (i / 2);
        temp[j] = block[i];
    }
    block = temp;
}

void inverseDifusion(vector<unsigned char> &block){
    vector<unsigned char> temp(block.size());
    for (int i = 0; i < block.size(); i++){
        int j = (i % 2 == 0) ? (block.size() - 1 - i / 2) : (i / 2);
        temp[i] = block[j];
    }

    for(int i = temp.size() - 1; i >= 1; i--){
        temp[i] ^= temp[i - 1];
    }
    
    for(int i = 0; i < (int)temp.size(); i++){
        temp[i] = rotateRight(temp[i], i + 1);
    }
    block = temp;
}

void inverseConfusion(vector<unsigned char> &block, const vector<unsigned char> &subkey, int round){
    for(int i = 0; i < block.size(); i++){
        int tmp = (int)block[i] - (int)(i * i) - round * 7;
        tmp = (tmp % 256 + 256) % 256;
        block[i] = (unsigned char)(tmp ^ subkey[i % subkey.size()]);
    }
}

vector<unsigned char> encryptBlock(vector<unsigned char> block, const string &key){
    for(int round = 0; round < TOTAL_ROUNDS; round++){
        vector<unsigned char> subkey = generateSubkey(key, round);
        confusion(block, subkey, round);
        difusion(block);
    }
    return block;
}

vector<unsigned char> decryptBlock(vector<unsigned char> block, const string &key){
    for(int round = TOTAL_ROUNDS-1; round >= 0; round--){
        vector<unsigned char> subkey = generateSubkey(key, round);
        inverseDifusion(block);
        inverseConfusion(block, subkey, round);
    }
    return block;
}

vector<unsigned char> padBlock(const vector<unsigned char>& data){
    vector<unsigned char> padded = data;
    int padding = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    if(padding == BLOCK_SIZE) padding = 0;
    
    for(int i = 0; i < padding; i++){
        padded.push_back(static_cast<unsigned char>(padding));
    }
    return padded;
}

vector<unsigned char> unpadBlock(const vector<unsigned char>& data){
    if(data.empty()) return data;
    
    unsigned char padding = data[data.size() - 1];
    if(padding > 0 && padding <= BLOCK_SIZE){
        for(size_t i = data.size() - padding; i < data.size(); i++){
            if(data[i] != padding){
                return data; 
            }
        }
        vector<unsigned char> unpadded = data;
        unpadded.resize(data.size() - padding);
        return unpadded;
    }
    return data;
}

vector<vector<unsigned char>> splitIntoBlocks(const vector<unsigned char>& data){
    vector<vector<unsigned char>> blocks;
    
    for(size_t i = 0; i < data.size(); i += BLOCK_SIZE){
        vector<unsigned char> block;
        for(int j = 0; j < BLOCK_SIZE && i + j < data.size(); j++){
            block.push_back(data[i + j]);
        }
        blocks.push_back(block);
    }
    
    return blocks;
}

vector<unsigned char> encryptText(const string& text, const string& key){
    vector<unsigned char> data(text.begin(), text.end());
    vector<unsigned char> padded = padBlock(data);
    vector<vector<unsigned char>> blocks = splitIntoBlocks(padded);
    
    vector<unsigned char> encrypted;
    for(auto& block : blocks){
        vector<unsigned char> encryptedBlock = encryptBlock(block, key);
        encrypted.insert(encrypted.end(), encryptedBlock.begin(), encryptedBlock.end());
    }
    
    return encrypted;
}

string decryptText(const vector<unsigned char>& encrypted, const string& key, bool& validKey) {
    vector<vector<unsigned char>> blocks = splitIntoBlocks(encrypted);
    
    vector<unsigned char> decrypted;
    for(auto& block : blocks) {
        vector<unsigned char> decryptedBlock = decryptBlock(block, key);
        decrypted.insert(decrypted.end(), decryptedBlock.begin(), decryptedBlock.end());
    }
    
    validKey = false;
    
    if(decrypted.empty()) {
        return "";  
    }
    
    unsigned char padding = decrypted[decrypted.size() - 1];
    
    if(padding > 0 && padding <= BLOCK_SIZE) {
        if(decrypted.size() >= padding) {
            validKey = true;
            for(size_t i = decrypted.size() - padding; i < decrypted.size(); i++) {
                if(decrypted[i] != padding) {
                    validKey = false;
                    break;
                }
            }
        }
    }
    
    if(validKey) {
        vector<unsigned char> unpadded = decrypted;
        unpadded.resize(decrypted.size() - padding);
        return string(unpadded.begin(), unpadded.end());
    }
    return "";
}

bool saveToFile(const string& filename, const string& content){
    ofstream file(filename);
    if(!file.is_open()){
        cout << "Error: Could not open file for writing." << endl;
        return false;
    }
    file << content;
    file.close();
    return true;
}

bool readFromFile(const string& filename, string& content){
    ifstream file(filename);
    if(!file.is_open()){
        cout << "Error: Could not open file for reading." << endl;
        return false;
    }
    stringstream buffer;
    buffer << file.rdbuf();
    content = buffer.str();
    file.close();
    return true;
}

void encryptMenu(){
    string text, key;
    cout << "\n=== ENCRYPT TEXT ===" << endl;
    
    cout << "Enter text to encrypt (max 100 characters): ";
    getline(cin, text);
    
    if(text.length() > 100){
        text = text.substr(0, 100);
        cout << "Text truncated to 100 characters." << endl;
    }
    
    cout << "Enter key (max 16 characters): ";
    getline(cin, key);
    
    if(key.length() > 16){
        key = key.substr(0, 16);
        cout << "Key truncated to 16 characters." << endl;
    }
    
    if(key.empty()){
        cout << "Error: Key cannot be empty." << endl;
        return;
    }
    
    cout << "\nProcessing..." << endl;
    vector<unsigned char> encrypted = encryptText(text, key);
    string hexResult = bytesToHexString(encrypted);
    
    cout << "Text encrypted successfully!" << endl;
    cout << "Original text: \"" << text << "\"" << endl;
    cout << "Encrypted text (hex): " << hexResult << endl;
    
    // Save to file
    string filename;
    cout << "\nEnter filename to save encrypted text: ";
    getline(cin, filename);
    
    if(saveToFile(filename, hexResult)){
        cout << "Encrypted text saved to: " << filename << endl;
    } else {
        cout << "Failed to save file." << endl;
    }
}

void decryptMenu(){
    string filename, key;
    cout << "\n=== DECRYPT TEXT ===" << endl;
    
    cout << "Enter filename with encrypted text: ";
    getline(cin, filename);
    
    string hexContent;
    if(!readFromFile(filename, hexContent)){
        cout << "Could not read file: " << filename << endl;
        return;
    }
    
    cout << "Enter decryption key: ";
    getline(cin, key);
    
    if(key.empty()){
        cout << "Error: Key cannot be empty." << endl;
        return;
    }
    
    vector<unsigned char> encryptedData;
    if(!hexStringToBytes(hexContent, encryptedData)){
        cout << "Invalid hexadecimal format in file." << endl;
        return;
    }
    
    cout << "\nDecrypting..." << endl;
    bool validKey;
    string decryptedText = decryptText(encryptedData, key, validKey);
    
    if(!validKey || decryptedText.empty()){
        cout << "DECRYPTION FAILED: Invalid key or corrupted data!" << endl;
        cout << "The key provided does not match the encryption key." << endl;
    } else {
        cout << "Decryption successful!" << endl;
        cout << "Decrypted text: \"" << decryptedText << "\"" << endl;
        
    }
}

int main(){
    int choice;
    
    do {
        cout << "\n=== BITCASCADE ENCRYPTION SYSTEM ===" << endl;
        cout << "1. Encrypt Text" << endl;
        cout << "2. Decrypt Text" << endl;
        cout << "3. Exit" << endl;
        cout << "Choose option: ";
        cin >> choice;
        cin.ignore(); // Clear newline
        
        switch(choice){
            case 1:
                encryptMenu();
                break;
            case 2:
                decryptMenu();
                break;
            case 3:
                cout << "Thank you for using BitCascade!" << endl;
                break;
            default:
                cout << "Invalid option. Please try again." << endl;
        }
        
    } while(choice != 3);
    
    return 0;
}