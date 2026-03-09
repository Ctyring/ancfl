#ifndef __ANCFL_LIBRARY_H__
#define __ANCFL_LIBRARY_H__

#include <memory>
#include "module.h"

namespace ancfl {

class Library {
   public:
    static Module::ptr GetModule(const std::string& path);
};

}  // namespace ancfl

#endif



