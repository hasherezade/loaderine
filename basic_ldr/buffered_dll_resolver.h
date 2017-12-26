#pragma once

#include "peconv.h"

#include <map>
#include <iostream>

class buffered_dlls_resolver : peconv::default_func_resolver {
    public:

    void redirect_module(std::string dll_name, HMODULE dll_module ) 
    {
        hooks_map[dll_name] = dll_module;
    }

    virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name)
    {
        std::map<std::string, HMODULE>::iterator itr = hooks_map.find(lib_name);
        if (itr != hooks_map.end()) {
            HMODULE dll_module = itr->second;
            FARPROC hProc = peconv::get_exported_func(dll_module, func_name);
#ifdef _DEBUG
            std::cout << ">>>>>>Replacing: " << func_name << " by: " << hProc << std::endl;
#endif
            return hProc;
        }
        return peconv::default_func_resolver::resolve_func(lib_name, func_name);
    }
    private:
    std::map<std::string, HMODULE> hooks_map;
};
