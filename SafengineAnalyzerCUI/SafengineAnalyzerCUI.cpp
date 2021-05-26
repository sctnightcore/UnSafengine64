#include <iostream>
#include <fstream>
#include <string>
#include "Windows.h"
#include <sstream>

using namespace std;

string PIN_DIR = "C:\\pin";
string PINTOOL_DIR = "C:\\pintool";
string PINEXE;
string PINTOOL64;
string CONFIG = "UnSafengine64.cfg";

string get_exe_path() {
	wchar_t buffer[MAX_PATH];
	GetModuleFileName(NULL, (LPWSTR)buffer, MAX_PATH);
	wstring ws(buffer);
	string current_directory(ws.begin(), ws.end());
	string::size_type pos = current_directory.find_last_of("\\/");
	return current_directory.substr(0, pos);
}

string get_working_path() {
	wchar_t buffer[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, buffer);
	wstring ws(buffer);
	string working_directory(ws.begin(), ws.end());
	return working_directory;
}

int read_config_file(string config_file) {
	CONFIG = get_exe_path() + "\\" + CONFIG;

	ifstream infile(CONFIG);
	if (!infile) {
		CONFIG = PINTOOL_DIR + "\\" + CONFIG;
		infile.open(CONFIG);
		if (!infile) {
			// if no config file, 
			// set default path
			PINEXE = PIN_DIR + "\\pin.exe";
			PINTOOL64 = PINTOOL_DIR + "\\UnSafengine64.dll";
			return 0;
		}		
	}

	string line;

	while (infile.eof()) {
		getline(infile, line);
		if (line.find("PIN_DIR") != string::npos) {
			size_t pos = line.find("=");
			PIN_DIR = line.substr(pos + 1);
		}
		else if (line.find("PINTOOL_DIR") != string::npos) {
			size_t pos = line.find("=");
			PINTOOL_DIR = line.substr(pos + 1);
		}
	}
	PINEXE = PIN_DIR + "\\pin.exe";	
	PINTOOL64 = PINTOOL_DIR + "\\SafengineAnalyzer.dll";	
	return 1;
}

int check_output_file(string out_file_path) {
	if (out_file_path.substr(0, 2) == ".\\") {
		out_file_path = out_file_path.substr(2);
	}
	out_file_path = get_working_path() + "\\" + out_file_path;
	cout << out_file_path << endl;
	ifstream infile(out_file_path);
	if (!infile) {
		return 0;
	}
	return -1;
}


int main(int argc, char** argv)
{
	string option, exe_file_name;
	string cmd_line;		

	if (argc < 3 || argc % 2 == 0) {
		cout << "Usage: " << endl;
		cout << "    UnSafengine64.exe -deob [-log log_file_name] [-dmp dump_file_name] exe_file_name " << endl;
		cout << "    or" << endl;
		cout << "    UnSafengine64.exe -trace [-log log_file_name] exe_file_name" << endl;
		cout << "    UnSafengine64.exe -pauseatoep [-log log_file_name] exe_file_name" << endl;
		exit(-1);
	}

	read_config_file(CONFIG);
	
	cmd_line = PINEXE + " -t " + PINTOOL64;	
	option = string(argv[1]);	
	if (option == "-deob") {
		cmd_line += " -dump";
	}
	else if (option == "-trace") {
		cmd_line += " -trace";
	}
	else if (option == "-pauseatoep") {
		cmd_line += " -pauseatoep ";
	}
	else {
		cout << "incorrect option!" << endl;
		exit(1);
	}
	exe_file_name = string(argv[argc - 1]);

	for (size_t i = 2; i < argc - 1; i += 2) {
		string opt = string(argv[i]);
		if (opt == "-log") {
			cmd_line += " -log " + string(argv[i + 1]);
		}
		else if (opt == "-dump") {
			cmd_line += " -dmp " + string(argv[i + 1]);
		}
	}


	cmd_line += " -- " + exe_file_name;	
	cout << cmd_line << endl;
	system(cmd_line.c_str());
	string out_file = exe_file_name.substr(0, exe_file_name.length() - 4) + "_dmp.exe";	
	if (check_output_file(out_file)) {
		cout << out_file << " is generated." << endl;
	}
	else {
		cout << "Failed to deobfuscate! Check log file." << endl;
	}	
}
