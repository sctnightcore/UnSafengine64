// PackerDetector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <fstream>
#include <set>

using namespace std;

int extract_api_call(char file_name[], set<string>& api_set) {

    ifstream input_file(file_name);

    if (!input_file.is_open()) {
        return 0;
    }

    string line;
    string api;
    while (getline(input_file, line)) {
        if (line.substr(0, 3) == "API") {
            size_t pos = line.rfind(':');
            api = line.substr(pos + 1);
            api_set.insert(api);
        }     
    }

    return 1;
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        cout << "Usage:\n";
        cout << "  PackerDetector.exe -i trace_file -o api_set_file.txt\n";
        cout << "    or\n";
        cout << "  PackerDetector.exe -i trace_file\n";
        exit(0);
    }
    
    char* input_file = NULL;
    char* output_file = NULL;
    for (size_t i = 1; i < argc; i++) {
        if (string(argv[i]) == "-i") {
            input_file = argv[i + 1];
        }
        if (string(argv[i]) == "-o") {
            output_file = argv[i + 1];
        }
    }

    set<string> api_set;
    extract_api_call(input_file, api_set);

    for (auto api : api_set) {
        cout << api << endl;
    }

}
