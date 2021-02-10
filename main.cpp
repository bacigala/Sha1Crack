
#include <iostream>
#include <fstream>
#include <sstream>
#include <cctype>
#include <vector>
#include <string>
#include <regex> 
#include <string.h> 
#include <algorithm>
#include <list>
#include <thread>
#include <mutex>
#include <chrono>

#pragma warning(push, 0)        
    // SHA1 https://github.com/983/SHA1
    #include "sha1.hpp"
#pragma warning(pop)

// symbol groups
const std::string SMALL_LETTERS = "abcdefghijklmnopqrstuvwxyz";
const std::string CAPITAL_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string DIGITS = "0123456789";

// parameters
const uint32_t MAX_PASSWORD_LENGTH = 32;

// globals
size_t g_passwords_tested = 0;
std::mutex g_passwords_tested_mutex;
size_t g_passwords_found = 0;
std::mutex g_passwords_found_mutex;


void exitWithError(const std::string& message = "Unexpected error.", const int& errNo = 2)
{
    std::cout << message << '\n';
    exit(errNo);
}

void checkHashFormat(const std::string& hash)
{
    if (hash.length() != 40)
        exitWithError("Invalid hash format. SHA1 hash has to be 40 characters long.");
    for (char ch : hash)
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')))
            exitWithError("Invalid hash format.");
}

bool checkHash(const std::string& password, const std::string& hash)
{
    char passwordHash[SHA1_HEX_SIZE];
    sha1(password.c_str()).finalize().print_hex(passwordHash);
    bool result = !hash.compare(passwordHash);
    if (result) {
        const std::lock_guard<std::mutex> lock(g_passwords_found_mutex);
        ++g_passwords_found;
    }
    const std::lock_guard<std::mutex> lock(g_passwords_tested_mutex);
    ++g_passwords_tested;
    return result;
}

bool bruteForceRecursive(
        std::string& password, size_t position, const std::string& wantedHash,
        const std::string& salt, const std::vector<char>& mask)
{
    // check
    if (position == mask.size()) {
        bool passwordFound = checkHash(password + salt, wantedHash);
        if (passwordFound || salt.empty())
            return passwordFound;
        return checkHash(salt + password, wantedHash);
    }
    
    // recursive call
    /*
    pattern
        [0-9],[a-z],[A-Z] represented by themselves
        # - any number
        @ - small letter
        & - capital letter
        ? - anything
    */
    char curMaskSymbol = mask.at(position);

    // "hard-masked" symbol
    if (std::isalnum(curMaskSymbol)) {
        password[position] = curMaskSymbol;
        return bruteForceRecursive(password, position + 1, wantedHash, salt, mask);
    }

    if (curMaskSymbol == '?' || curMaskSymbol == '@')
        for (char ch : SMALL_LETTERS) {
            password[position] = ch;
            if (bruteForceRecursive(password, position+1, wantedHash, salt, mask))
                return true;
        }
    if (curMaskSymbol == '?' || curMaskSymbol == '&') 
        for (char ch : CAPITAL_LETTERS) {
            password[position] = ch;
            if (bruteForceRecursive(password, position+1, wantedHash, salt, mask))
                return true;
        }
    if (curMaskSymbol == '?' || curMaskSymbol == '#')
    for (char ch : DIGITS) {
        password[position] = ch;
        if (bruteForceRecursive(password, position+1, wantedHash, salt, mask))
            return true;
    }

    return false;
}

void bruteForce(const std::string hash, const std::string salt, const std::vector<std::vector<char>> masks)
{
    std::string password;
    bool passwordFound = false;
    for (auto mask : masks) {
        password.resize(mask.size());
        size_t position = 0;
        passwordFound = bruteForceRecursive(password, position, hash, salt, mask);
        if (passwordFound)
            break;
    }
    std::cout << hash << char(9) << (passwordFound ? password : "N\\A") << '\n';
}

void generateMasksRecursive(
    std::vector<std::vector<char>>& masks, const std::vector<char>& expandedIntervals,
    const std::vector<bool>& fixed, const std::vector<size_t>& nextHop, size_t fixedTillHere,
    const std::vector<size_t>& fixedTillEnd, size_t pos, std::vector<char>& mask)
{
    if (pos >= expandedIntervals.size()) {
        if (!mask.empty())
            masks.push_back(mask);
        return;
    }

    if (!fixed.at(pos))
        generateMasksRecursive(masks, expandedIntervals, fixed, nextHop, fixedTillHere, fixedTillEnd, nextHop.at(pos), mask);


    if ((fixedTillHere + 1 + fixedTillEnd.at(pos)) <= MAX_PASSWORD_LENGTH) {
        mask.push_back(expandedIntervals.at(pos));
        generateMasksRecursive(masks, expandedIntervals, fixed, nextHop, fixedTillHere + 1, fixedTillEnd, pos + 1, mask);
        mask.pop_back();
    }
}

std::vector<std::vector<char>> generateMasks(std::string& pattern)
{
    if (pattern.empty())
        pattern.append("?*");

    /*
    expanded-intervals legend
        [0-9],[a-z],[A-Z] represented by themselves
        # - any number
        @ - small letter
        & - capital letter
        ? - anything
    */

    // expand intervals
    std::vector<char> expandedIntervals;
    std::vector<bool> fixed;
    for (size_t i = 0; i < pattern.length(); i++) {
        char ch = pattern.at(i);
        switch (ch) {
        case '\\':
            i++;
            if (i >= pattern.length())
                exitWithError("Invalid arguments. Check password pattern.", 3);
            switch (pattern.at(i)) {
            case 'A':
                expandedIntervals.push_back('&');
                break;
            case 'a':
                expandedIntervals.push_back('@');
                break;
            case 'd':
                expandedIntervals.push_back('#');
                break;
            default:
                exitWithError("Invalid arguments. Check password pattern.", 4);
            }
            fixed.push_back(true);
            break;
        case '?':
            expandedIntervals.push_back('?');
            fixed.push_back(true);
            break;
        case '*':
            [[fallthrough]];
        case '{':
        {
            // check legal position
            if (expandedIntervals.empty() || !(std::isalnum(pattern.at(i - 1)) || pattern.at(i - 1) == '?'))
                exitWithError("Invalid arguments. Unexpected interval in pattern.");
            char intervalledChar = expandedIntervals.at(expandedIntervals.size() - 1);

            // parse interval values
            size_t min = 0, max = MAX_PASSWORD_LENGTH;
            if (ch == '{') {
                size_t intervalLength = 1;
                while (i + intervalLength < pattern.size() && pattern.at(i + intervalLength) != '}')
                    intervalLength++;
                intervalLength++; // terminating '}'
                if (i + intervalLength - 1 >= pattern.size())
                    exitWithError("Invalid pattern. Check intervals.");
                std::regex regexp("\\{\\s*([0-9]+)\\s*\\,\\s*([0-9]+)\\s*\\}");
                std::smatch m;
                std::string interval = pattern.substr(i, intervalLength);
                regex_search(interval, m, regexp);
                min = std::stoi(m[1].str());
                max = std::stoi(m[2].str());   
                i += intervalLength - 1; // for loop will do +1
            }

            if (min > max)
                exitWithError("Invalid pattern. Check Intervals.", 3);

            if (min == 0)
                fixed.at(fixed.size() - 1) = false;
            else
                for (size_t fixedOccurences = 0; fixedOccurences < min - 1; fixedOccurences++) {
                    expandedIntervals.push_back(intervalledChar);
                    fixed.push_back(true);
                }

            for (size_t voidOccurences = (min ? 0 : 1); voidOccurences < max-min; voidOccurences++) {
                expandedIntervals.push_back(intervalledChar);
                fixed.push_back(false);
            }

            break;
        }
        default:
            if (!std::isalnum(pattern.at(i)))
                exitWithError("Invalid arguments. Check password pattern. unexpeced " + ch);
            expandedIntervals.push_back(ch);
            fixed.push_back(true);
        }
    }

    // create support arrays
    /*
    * nexthop: if expandedIntervals[i] is not selected to mask in recursion, 
    * next to be evalueated in recursion is expandedIntervals[nextHop[i]]
    * => this skips the rest of the interval
    */
    std::vector<size_t> nextHop;
    size_t lastFixedOrOther = expandedIntervals.size();
    char lastSeenChar = expandedIntervals.at(expandedIntervals.size() - 1);
    for (long long i = expandedIntervals.size() - 1; i >= 0; i--) {
        if (lastSeenChar != expandedIntervals.at(i)) {
            lastFixedOrOther = i + 1;
            lastSeenChar = expandedIntervals.at(i);
        }
        
        if (fixed.at(i)) {
            nextHop.push_back(i + 1);
            lastFixedOrOther = i;
        }
        else
            nextHop.push_back(lastFixedOrOther);
    }
    std::reverse(nextHop.begin(), nextHop.end());
    std::vector<size_t> fixedTillEnd;
    size_t noFixed = 0;
    for (long long i = expandedIntervals.size() - 1; i >= 0; i--) {
        fixedTillEnd.push_back(noFixed);
        if (fixed.at(i))
            noFixed++;
    }
    std::reverse(fixedTillEnd.begin(), fixedTillEnd.end());

    // generate masks recursively
    std::vector<std::vector<char>> masks;
    std::vector<char> mask;
    generateMasksRecursive(masks, expandedIntervals, fixed, nextHop, 0, fixedTillEnd, 0, mask);

    return masks;
}

void printNotification(const std::chrono::steady_clock::time_point& start) {
    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    size_t duration = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();

    const std::lock_guard<std::mutex> lock1(g_passwords_tested_mutex);
    const std::lock_guard<std::mutex> lock2(g_passwords_found_mutex);

    std::cout << " # INFO: \n";
    std::cout << "   # Passwords tested:\t" << g_passwords_tested << '\n';
    std::cout << "   # Passwords found:\t" << g_passwords_found << '\n';
    std::cout << "   # Time elapsed:\t" << duration << " seconds\n";
    if (duration)
        std::cout << "   # Average speed:\t" << (g_passwords_tested / duration) << " passwords/second\n";
}

void notificationThread(const std::chrono::steady_clock::time_point& start) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        printNotification(start);
    }    
}

int main(int argc, char* argv[])
{
    // parse command line arguments
    std::string salt, inputFileName, dictionaryFileName, pattern, wantedHash;
    bool multiThread = false;
    
    for (int i = 1; i < argc; i++) {
        std::string argument = argv[i];
        if (!argument.compare("-S") || !argument.compare("--salt")) {
            if (i + 1 >= argc)
                exitWithError("Invalid arguments. Salt expected but not found.");
            salt = argv[++i];
        } 
        else if (!argument.compare("-I") || !argument.compare("--input")) {
            if (i + 1 >= argc)
                exitWithError("Invalid arguments. Input file name expected but not found.");
            inputFileName = argv[++i];
        }
        else if (!argument.compare("-P") || !argument.compare("--pattern")) {
            if (i + 1 >= argc)
                exitWithError("Invalid arguments. Password pattern expected but not found.");
            pattern = argv[++i];
        }
        else if (!argument.compare("-MT")) {
            multiThread = true;
        }
        else if (!argument.compare("-D") || !argument.compare("--dictionary")) {
            if (i + 1 >= argc)
                exitWithError("Invalid arguments. Dictionary file name expected but not found.");
            dictionaryFileName = argv[++i];
        }
        else {
            wantedHash = argument;
        }
    }

    //salt
    if (salt.length() > MAX_PASSWORD_LENGTH)
        exitWithError("Salt too long. Max password length is " + std::to_string(MAX_PASSWORD_LENGTH) + " characters.");
    for (char ch : salt)
        if (!std::isalnum(ch))
            exitWithError("Salt can only contain alphanumeric symbols.");
    
    //input
    std::ifstream input;
    std::vector<std::string> hashes;
    if (!inputFileName.empty()) {
        input.open(inputFileName);
        if (!input.is_open())
            exitWithError("Unable to open input file " + inputFileName);
        else {
            std::cout << " # INFO: Loading input file.\n";
            std::string inputLine;
            while (std::getline(input, inputLine)) {
                if (inputLine.empty())
                    continue;
                checkHashFormat(inputLine);
                hashes.push_back(inputLine);
            }
        }
    }

    //dictionary
    std::ifstream dictionary;
    std::vector<std::string> dictionaryWords;
    if (!dictionaryFileName.empty()) {
        dictionary.open(dictionaryFileName);
        if (!dictionary.is_open())
            exitWithError("Unable to open dictionary file " + dictionaryFileName);
        else {
            std::cout << " # INFO: Loading dictionary file.\n";
            std::string dictionaryLine;
            while (std::getline(dictionary, dictionaryLine)) {
                if (dictionaryLine.empty())
                    continue;
                dictionaryWords.push_back(dictionaryLine);
            }
        }
    }

    //wanted hash
    if (!wantedHash.empty()) {
        checkHashFormat(wantedHash);
        hashes.push_back(wantedHash);
    } else if (!input.is_open())
        exitWithError("Please define hash or input file.");
    

    // CRACKING

    std::cout << " # INFO: Crack start...\n";
    auto start = std::chrono::high_resolution_clock::now();
    // start notification thread
    std::thread notificationThread(notificationThread, start);
    notificationThread.detach();
    
    std::vector<std::thread> threads;
  
    // dictionary attack
    if (!dictionaryWords.empty()) {
        std::cout << " # INFO: Dictionary attack START.\n";
        for (auto hashIterator = hashes.begin(); hashIterator != hashes.end();) {
            std::string hash = *hashIterator;
            bool hasPassword = false;
            for (auto dictionaryWord : dictionaryWords) {
                if (checkHash(dictionaryWord, hash)) {
                    std::cout << hash << '\t' << dictionaryWord << '\n';
                    hasPassword = true;
                    break;
                }
            }
            if (hasPassword)
                hashIterator = hashes.erase(hashIterator);
            else
                hashIterator++;
        }
        std::cout << " # INFO: Dictionary attack END.\n";
        printNotification(start);
    }

    size_t passwordsTestedInDictionary = g_passwords_tested;

    // all passwords found
    if (hashes.empty())
        return 0;

    // brute-force attack
    std::cout << " # INFO: Brute-force attack START.\n";
    std::cout << " # INFO: Generating masks.\n";
    auto masks = generateMasks(pattern);
    std::cout << " # INFO: Masks generated. TOTAL: " << masks.size() << '\n';
    
    // try shorter masks first
    std::sort(masks.begin(), masks.end(), [](const std::vector<char>& lhs, const std::vector<char>& rhs) -> bool {
            return lhs.size() < rhs.size();
        });

    g_passwords_tested = 0;
    start = std::chrono::high_resolution_clock::now();

    // crack
    if (multiThread) {
        for (auto hash : hashes) 
            threads.push_back(std::thread(bruteForce, hash, salt, masks));
        for (auto& thread : threads)
            thread.join();
    }
    else {
        for (auto hash : hashes)
            bruteForce(hash, salt, masks);
    }

    std::cout << " # INFO: Brute-force attack END.\n";
    std::cout << " # BRUTE-FORCE SUMMARY:\n";
    printNotification(start);
    
    std::cout << " # GLOBAL SUMMARY:\n";
    std::cout << "   # total passwords tested: " << passwordsTestedInDictionary + g_passwords_tested << '\n';

	return 0;
}
