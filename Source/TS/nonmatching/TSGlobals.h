#include <stdint.h>

class cITSNeighborhood;

class cITSGlobals {
public:
    virtual cITSNeighborhood* GetNeighborhood();
};
namespace TS {
    cITSGlobals* Globals();
}