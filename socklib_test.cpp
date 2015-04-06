//
//  main.cpp
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
//	socklib::SockLib::luaRegLib(L, "socklib");
	socklib::SockLib::luaRegLib(L);
#else
//	socklib::SockTcp* tcp = socklib::SockLib::createTcp();
//	socklib::SockLib::destroy(tcp);
#endif

	// you need to edit this path
#ifdef _WIN32
	#define SCRIPT_DIR "Z:/OSX/Users/LX/CC/MyLua/SockLib/"
#else
	#define SCRIPT_DIR "/Users/LX/CC/MyLua/SockLib/"
#endif
	
	
#if 1 && SOCKLIB_TO_LUA
	socklib::SockLib::luaAddPath(SCRIPT_DIR "?.lua");
	socklib::SockLib::luaAddPath(SCRIPT_DIR "Mahjong/?.lua");
	
	socklib::SockLib::luaLoadFile(SCRIPT_DIR "socklib_test.lua", false);
//	socklib::SockLib::luaLoadFile(SCRIPT_DIR "example_tcp.lua", false);
//	socklib::SockLib::luaLoadFile(SCRIPT_DIR "Mahjong/App.lua", false);
//	socklib::SockLib::luaLoadFile(SCRIPT_DIR "Mahjong/Net/Handler.lua", false);

	while (1) {
		socklib::SockLib::poll();
	}
	
	return 0;
#endif
	
	string s;
	
	while (getline(cin, s)) {
		bool err = luaL_loadbuffer(L, s.c_str(), s.length(), 0) || lua_pcall(L, 0, 0, 0);
		if (err) {
			cerr << lua_tostring(L, -1);
			lua_pop(L, 1);
		}
	}
	
	lua_close(L);
	
    return 0;
}
