#include <SFML/Graphics.hpp>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
using namespace std;

const int BLOCK_SIZE = 8; 

unsigned char rotateLeft(unsigned char byte, int n){
    return (byte << n ) | (byte >> (8-n));
}

unsigned char rotateRight(unsigned char byte, int n){
    return (byte >> n) | (byte << (8-n));
}

vector<unsigned char> generateSubkey(const string& key, const vector<unsigned char>& block, int round){
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
    for(int round = 0; round < 5; round++){
        vector<unsigned char> subkey = generateSubkey(key, block, round);
        confusion(block, subkey, round);
        difusion(block);
    }
    return block;
}

vector<unsigned char> decryptBlock(vector<unsigned char> block, const string &key){
    for(int round = 4; round >= 0; round--){
        vector<unsigned char> subkey = generateSubkey(key, block, round);
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
        padded.push_back((unsigned char)padding);
    }
    return padded;
}

// Quitar el relleno del bloque
vector<unsigned char> unpadBlock(const vector<unsigned char>& data){
    if(data.empty()) return data;
    
    unsigned char padding = data[data.size() - 1];
    if(padding > 0 && padding <= BLOCK_SIZE){
        vector<unsigned char> unpadded = data;
        unpadded.resize(data.size() - padding);
        return unpadded;
    }
    return data;
}

// Dividir el texto en bloques
vector<vector<unsigned char>> splitIntoBlocks(const vector<unsigned char>& data){
    vector<vector<unsigned char>> blocks;
    
    for(int i = 0; i < data.size(); i += BLOCK_SIZE){
        vector<unsigned char> block;
        for(int j = 0; j < BLOCK_SIZE && i + j < data.size(); j++){
            block.push_back(data[i + j]);
        }
        blocks.push_back(block);
    }
    
    return blocks;
}

// Cifrar texto completo
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

// Descifrar texto completo
string decryptText(const vector<unsigned char>& encrypted, const string& key){
    vector<vector<unsigned char>> blocks = splitIntoBlocks(encrypted);
    
    vector<unsigned char> decrypted;
    for(auto& block : blocks){
        vector<unsigned char> decryptedBlock = decryptBlock(block, key);
        decrypted.insert(decrypted.end(), decryptedBlock.begin(), decryptedBlock.end());
    }
    
    vector<unsigned char> unpadded = unpadBlock(decrypted);
    return string(unpadded.begin(), unpadded.end());
}

// =======================================================
// ===================== INTERFAZ CON SFML =======================
class CryptoGUI {
private:
    sf::RenderWindow window;
    sf::Font font;
    
    sf::Text inputLabel, keyLabel, cipherLabel, decryptedLabel;
    sf::Text titleText;
    
    sf::RectangleShape inputBox, keyBox, cipherBox, decryptedBox;
    sf::Text inputDisplay, keyDisplay, cipherDisplay, decryptedDisplay;

    sf::RectangleShape encryptButton, decryptButton, saveButton, loadButton, clearButton;
    sf::Text encryptButtonText, decryptButtonText, saveText, loadText, clearText;

    sf::Text statusText;

    string inputText, keyText, encryptedHex, decryptedText;
    string ciphertextFilename = "ciphertext.txt";
    bool inputActive = false, keyActive = false;

    // ==== CURSOR ====
    bool showCursor = true;
    sf::Clock cursorClock;
    float cursorInterval = 0.5f;

    // ==== FUNCIONES DE AYUDA PARA HEX ====
    static bool parseHexString(const string &hexStr, vector<unsigned char> &out, string &errMsg) {
        out.clear();
        string s;
        for (char c : hexStr) {
            if (isxdigit((unsigned char)c)) s.push_back(c);
            else if (isspace((unsigned char)c)) continue;
            else { errMsg = "Hex invalido: '" + string(1, c) + "'"; return false; }
        }
        if (s.size() % 2 != 0) { errMsg = "Hex invalido: longitud impar."; return false; }
        try {
            for (size_t i = 0; i < s.size(); i += 2) {
                string byteStr = s.substr(i, 2);
                unsigned int val = stoi(byteStr, nullptr, 16);
                out.push_back((unsigned char)val);
            }
        } catch (...) { errMsg = "Error al convertir hex."; return false; }
        return true;
    }

    bool saveCipherToFile(const string &hexText) {
        if (hexText.empty()) return false;
        ofstream ofs(ciphertextFilename, ios::out | ios::trunc);
        if (!ofs.is_open()) return false;
        ofs << hexText;
        ofs.close();
        return true;
    }

    bool loadCipherFromFile(string &hexText) {
        ifstream ifs(ciphertextFilename, ios::in);
        if (!ifs.is_open()) return false;
        stringstream ss; ss << ifs.rdbuf();
        hexText = ss.str();
        while (!hexText.empty() && isspace((unsigned char)hexText.back())) hexText.pop_back();
        ifs.close();
        return true;
    }

public:
    CryptoGUI() : window(sf::VideoMode(900, 700), "BitCascade - SFML") {
        if (!font.loadFromFile("arial.ttf")) {
            // Intentar cargar desde ruta común de Windows
            font.loadFromFile("C:/Windows/Fonts/arial.ttf");
        }
        setupUI();

        inputActive = true;
        cursorClock.restart();
        updateDisplay();
    }

    void setupUI() {
        titleText.setFont(font);
        titleText.setString("BitCascade Algorithm");
        titleText.setCharacterSize(28);
        titleText.setFillColor(sf::Color::Cyan);
        titleText.setPosition(180, 20);

        // Configurar cajas de texto
        inputBox.setSize({400, 80});
        inputBox.setPosition(50, 100);
        inputBox.setFillColor(sf::Color(50, 50, 80));
        inputBox.setOutlineColor(sf::Color::White);
        inputBox.setOutlineThickness(2);

        keyBox.setSize({300, 40});
        keyBox.setPosition(50, 210);
        keyBox.setFillColor(sf::Color(50, 50, 80));
        keyBox.setOutlineColor(sf::Color::White);
        keyBox.setOutlineThickness(2);

        cipherBox.setSize({400, 80});
        cipherBox.setPosition(50, 280);
        cipherBox.setFillColor(sf::Color(50, 50, 80));
        cipherBox.setOutlineColor(sf::Color::White);
        cipherBox.setOutlineThickness(2);

        decryptedBox.setSize({400, 80});
        decryptedBox.setPosition(50, 390);
        decryptedBox.setFillColor(sf::Color(50, 50, 80));
        decryptedBox.setOutlineColor(sf::Color::White);
        decryptedBox.setOutlineThickness(2);

        // Configurar displays de texto
        inputDisplay.setFont(font);
        inputDisplay.setCharacterSize(16);
        inputDisplay.setFillColor(sf::Color::Yellow);
        inputDisplay.setPosition(60, 110);

        keyDisplay.setFont(font);
        keyDisplay.setCharacterSize(16);
        keyDisplay.setFillColor(sf::Color::Yellow);
        keyDisplay.setPosition(60, 220);

        cipherDisplay.setFont(font);
        cipherDisplay.setCharacterSize(14);
        cipherDisplay.setFillColor(sf::Color::Green);
        cipherDisplay.setPosition(60, 290);

        decryptedDisplay.setFont(font);
        decryptedDisplay.setCharacterSize(16);
        decryptedDisplay.setFillColor(sf::Color::Yellow);
        decryptedDisplay.setPosition(60, 400);

        // Etiquetas
        inputLabel.setFont(font);
        inputLabel.setString("Plaintext (max 100 chars):");
        inputLabel.setCharacterSize(16);
        inputLabel.setFillColor(sf::Color::White);
        inputLabel.setPosition(inputBox.getPosition().x, inputBox.getPosition().y - 25);

        keyLabel.setFont(font);
        keyLabel.setString("Key (max 16 chars):");
        keyLabel.setCharacterSize(16);
        keyLabel.setFillColor(sf::Color::White);
        keyLabel.setPosition(keyBox.getPosition().x, keyBox.getPosition().y - 25);

        cipherLabel.setFont(font);
        cipherLabel.setString("Ciphertext (Hex):");
        cipherLabel.setCharacterSize(16);
        cipherLabel.setFillColor(sf::Color::White);
        cipherLabel.setPosition(cipherBox.getPosition().x, cipherBox.getPosition().y - 25);

        decryptedLabel.setFont(font);
        decryptedLabel.setString("Decrypted Text:");
        decryptedLabel.setCharacterSize(16);
        decryptedLabel.setFillColor(sf::Color::White);
        decryptedLabel.setPosition(decryptedBox.getPosition().x, decryptedBox.getPosition().y - 25);

        // Botones
        setupButton(encryptButton, encryptButtonText, "ENCRYPT", 500, 100, sf::Color(0, 200, 0));
        setupButton(decryptButton, decryptButtonText, "DECRYPT", 500, 170, sf::Color(0, 100, 200));
        setupButton(saveButton, saveText, "SAVE CIPHER", 500, 240, sf::Color(120, 120, 120));
        setupButton(loadButton, loadText, "LOAD CIPHER", 500, 310, sf::Color(120, 120, 120));
        setupButton(clearButton, clearText, "CLEAN ALL", 500, 380, sf::Color(200, 50, 50));

        statusText.setFont(font);
        statusText.setCharacterSize(16);
        statusText.setFillColor(sf::Color::White);
        statusText.setPosition(50, 500);
        statusText.setString("Ready. Enter text and key, then click ENCRYPT.");
    }

    void setupButton(sf::RectangleShape &button, sf::Text &label, const string &text,
                     float x, float y, sf::Color color) {
        button.setSize({150, 50});
        button.setPosition(x, y);
        button.setFillColor(color);
        button.setOutlineColor(sf::Color::White);
        button.setOutlineThickness(2);

        label.setFont(font);
        label.setCharacterSize(16);
        label.setFillColor(sf::Color::White);
        label.setString(text);
        // Centrar texto en el botón
        sf::FloatRect textBounds = label.getLocalBounds();
        label.setPosition(x + (150 - textBounds.width) / 2, y + 15);
    }

    void run() {
        while (window.isOpen()) {
            handleEvents();
            handleCursor();
            render();
        }
    }

    void handleEvents() {
        sf::Event event;
        while (window.pollEvent(event)) {
            if (event.type == sf::Event::Closed) window.close();

            if (event.type == sf::Event::MouseButtonPressed) {
                auto mp = window.mapPixelToCoords({event.mouseButton.x, event.mouseButton.y});
                inputActive = inputBox.getGlobalBounds().contains(mp);
                keyActive = keyBox.getGlobalBounds().contains(mp);

                if (encryptButton.getGlobalBounds().contains(mp)) encryptData();
                else if (decryptButton.getGlobalBounds().contains(mp)) decryptData();
                else if (saveButton.getGlobalBounds().contains(mp)) {
                    if (saveCipherToFile(encryptedHex)) {
                        statusText.setString("Cipher saved to " + ciphertextFilename);
                        statusText.setFillColor(sf::Color::Green);
                    } else {
                        statusText.setString("Error saving file");
                        statusText.setFillColor(sf::Color::Red);
                    }
                } else if (loadButton.getGlobalBounds().contains(mp)) {
                    string loaded;
                    if (loadCipherFromFile(loaded)) {
                        encryptedHex = loaded;
                        cipherDisplay.setString(encryptedHex);
                        statusText.setString("Cipher loaded from " + ciphertextFilename);
                        statusText.setFillColor(sf::Color::Green);
                    } else {
                        statusText.setString("Error loading file");
                        statusText.setFillColor(sf::Color::Red);
                    }
                } else if (clearButton.getGlobalBounds().contains(mp)) {
                    inputText.clear();
                    keyText.clear();
                    encryptedHex.clear();
                    decryptedText.clear();
                    cipherDisplay.setString("");
                    decryptedDisplay.setString("");
                    updateDisplay();
                    statusText.setString("All fields cleaned");
                    statusText.setFillColor(sf::Color::Yellow);
                }
            }

            if (event.type == sf::Event::TextEntered) {
                if (event.text.unicode < 128) {
                    char c = static_cast<char>(event.text.unicode);
                    if (c == 8) { // BACKSPACE
                        if (inputActive && !inputText.empty()) inputText.pop_back();
                        else if (keyActive && !keyText.empty()) keyText.pop_back();
                    } else if (c >= 32) {
                        if (inputActive && inputText.length() < 100) inputText.push_back(c);
                        else if (keyActive && keyText.length() < 16) keyText.push_back(c);
                    }
                    updateDisplay();
                }
            }
        }
    }

    void handleCursor() {
        if (cursorClock.getElapsedTime().asSeconds() >= cursorInterval) {
            showCursor = !showCursor;
            cursorClock.restart();
            updateDisplay();
        }
    }

    void updateDisplay() {
        string cursorChar = (showCursor && inputActive) ? "|" : "";
        inputDisplay.setString(inputText + cursorChar);
        
        cursorChar = (showCursor && keyActive) ? "|" : "";
        keyDisplay.setString(keyText + cursorChar);
        
        decryptedDisplay.setString(decryptedText);
    }

    void encryptData() {
        if (inputText.empty() || keyText.empty()) {
            statusText.setString("Error: plaintext or key are empty");
            statusText.setFillColor(sf::Color::Red);
            return;
        }
        
        // Limitar a 100 caracteres si es necesario
        string textToEncrypt = inputText;
        if (textToEncrypt.length() > 100) {
            textToEncrypt = textToEncrypt.substr(0, 100);
            statusText.setString("Text truncated to 100 characters. Encrypting...");
        } else {
            statusText.setString("Encrypting...");
        }
        
        // Limitar clave a 16 caracteres
        string keyToUse = keyText;
        if (keyToUse.length() > 16) {
            keyToUse = keyToUse.substr(0, 16);
            statusText.setString(statusText.getString() + " Key truncated to 16 chars.");
        }
        
        statusText.setFillColor(sf::Color::Yellow);
        window.draw(statusText);
        window.display();
        
        try {
            vector<unsigned char> encrypted = encryptText(textToEncrypt, keyToUse);
            
            stringstream ss;
            ss << hex << setfill('0');
            for (auto c : encrypted) ss << setw(2) << (int)c << " ";
            encryptedHex = ss.str();
            
            cipherDisplay.setString(encryptedHex);
            statusText.setString("Encryption successful! Text length: " + to_string(textToEncrypt.length()) + " chars");
            statusText.setFillColor(sf::Color::Green);
        } catch (const exception& e) {
            statusText.setString("Encryption error: " + string(e.what()));
            statusText.setFillColor(sf::Color::Red);
        }
    }

    void decryptData() {
    if (encryptedHex.empty() || keyText.empty()) {
        statusText.setString("Error: no ciphertext or key");
        statusText.setFillColor(sf::Color::Red);
        return;
    }
    
    statusText.setString("Decrypting...");
    statusText.setFillColor(sf::Color::Yellow);
    window.draw(statusText);
    window.display();
    
    try {
        vector<unsigned char> encryptedBytes;
        string parseErr;
        if (!parseHexString(encryptedHex, encryptedBytes, parseErr)) {
            statusText.setString("Invalid hex: " + parseErr);
            statusText.setFillColor(sf::Color::Red);
            return;
        }
        
        string decryptedResult = decryptText(encryptedBytes, keyText);
        
        // Validación de la llave para desencriptar
        if (containsMostlyPrintableChars(decryptedResult)) {
            decryptedText = decryptedResult;
            decryptedDisplay.setString(decryptedText);
            statusText.setString("Decryption successful!");
            statusText.setFillColor(sf::Color::Green);
        } else {
            decryptedText = "[INVALID DATA - WRONG KEY]";
            decryptedDisplay.setString(decryptedText);
            statusText.setString("ERROR: Wrong key or corrupted data!");
            statusText.setFillColor(sf::Color::Red);
        }
        
    } catch (const exception& e) {
        statusText.setString("Decryption error: " + string(e.what()));
        statusText.setFillColor(sf::Color::Red);
    }
}

bool containsMostlyPrintableChars(const string& text) {
    if (text.empty()) return false;
    
    int printableCount = 0;
    for (char c : text) {
        // Caracteres imprimibles ASCII (32-126) + espacios + saltos de línea comunes
        if ((c >= 32 && c <= 126) || c == ' ' || c == '\n' || c == '\t' || c == '\r') {
            printableCount++;
        }
    }
    
    // Considerar válido si al menos el 80% son caracteres imprimibles
    return (float)printableCount / text.length() >= 0.8f;
}

    void render() {
        window.clear(sf::Color(30, 30, 60));
        
        // Dibujar todos los elementos
        window.draw(titleText);
        
        window.draw(inputLabel); window.draw(inputBox); window.draw(inputDisplay);
        window.draw(keyLabel); window.draw(keyBox); window.draw(keyDisplay);
        window.draw(cipherLabel); window.draw(cipherBox); window.draw(cipherDisplay);
        window.draw(decryptedLabel); window.draw(decryptedBox); window.draw(decryptedDisplay);
        
        window.draw(encryptButton); window.draw(encryptButtonText);
        window.draw(decryptButton); window.draw(decryptButtonText);
        window.draw(saveButton); window.draw(saveText);
        window.draw(loadButton); window.draw(loadText);
        window.draw(clearButton); window.draw(clearText);
        
        window.draw(statusText);
        
        window.display();
    }
};

int main() { 
    CryptoGUI gui; 
    gui.run();
    return 0;
}