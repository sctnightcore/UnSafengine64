#pragma once
#include <iostream>
#include <sstream>
#include <string>

typedef int LogLevel;

bool isEnabled(LogLevel l) {
    return true;
}

namespace logger {
    void log(std::ostream *fout, std::string const& msg) {
        *fout << msg;
    }
}

#define FLOG(Level, fout, What) \
  isEnabled(Level) && scoped_logger(fout).stream() << What

#define TLOG(fout, What) fout << What

struct scoped_logger
{
    scoped_logger(std::ostream* fout) : _fout(fout) {};
    std::stringstream& stream() { return _ss; }
    ~scoped_logger() { logger::log(_fout, _ss.str()); }
private:
    std::stringstream _ss;
    std::ostream* _fout;
};

int main() {
    FLOG(1, &std::cout, "Hello, " << "World!" << "wOW");
    TLOG(1, )
}