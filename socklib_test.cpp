//
//  socklib.test.cpp
//
//  Created by liangX on 15/3/21.
//  Copyright (c) 2015. All rights reserved.
//

extern "C" {
	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"
}

#include "SockLib.h"

using namespace std;

int main(int argc, const char * argv[])
{
	lua_State* L = luaL_newstate();
	luaL_openlibs(L);
	
#if SOCKLIB_TO_LUA
//	socklib::SockLib::mylua_regAs(L, "socklib");
	socklib::SockLib::mylua_reg(L);
	
//	socklib::SockTcp* tcp = socklib::SockLib::createTcp<>();
//	socklib::SockLib::destroy(tcp);
#endif
	
#if 1 && SOCKLIB_TO_LUA
//	luaL_dofile(L, "socklib_test.lua");
//	socklib::LuaHelper::debugScriptFile(L, "socklib_test.lua");
	socklib::LuaHelper::debugScriptFile(L, "/Users/LX/CC/MyLua/MyLua51Test/scripts/test.lua");

	while (1) {
		socklib::SockLib::poll();
	}
	
	return 0;
#endif
	
	string s;
	
	while (getline(cin,s)) {
		bool err = luaL_loadbuffer(L, s.c_str(), s.length(), 0) || lua_pcall(L, 0, 0, 0);
		if (err) {
			cerr << lua_tostring(L, -1);
			lua_pop(L, 1);
		}
	}
	
	lua_close(L);
	
    return 0;
}
