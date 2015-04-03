//
//  SockLib.h
//
//  Created by liangX<liangx.cn@qq.com> on 15/3/25.
//  Copyright (c) 2015. All rights reserved.
//

#ifndef __SOCKLIB_H__
#define __SOCKLIB_H__

#define SOCKLIB_VER			"1.0"

// export to LUA?
#ifndef SOCKLIB_TO_LUA
#define SOCKLIB_TO_LUA		1
#endif

// show debug message?
#if !defined(SOCKLIB_DEBUG) && (defined(DEBUG) || defined(_DEBUG))
#define SOCKLIB_DEBUG		1
#endif

// enable CRC32 RC4 MD5 SHA1 BASE64... ?
#ifndef SOCKLIB_ALG
#define SOCKLIB_ALG			1
#endif

// Member/Method's name case sensitivity?
// If turn it on
//		obj.XXX  == obj.xxx  == obj.XxX  ...
//		obj:XX() == obj:xx() == obj:Xx() ...
//
// 		(effect obj belongs to socklib only)
//
#ifndef SOCKLIB_NOCASE
#define SOCKLIB_NOCASE		1
#endif

// lib name in LUA
// you can change this name
#ifndef SOCKLIB_NAME
#define SOCKLIB_NAME		"socklib"
#endif

// use a cpp namespace?
// you can change this name
#if 1
#define SOCKLIB_NAMESPACE_BEGIN 	namespace socklib {
#define SOCKLIB_NAMESPACE_END 		}
#else
#define SOCKLIB_NAMESPACE_BEGIN
#define SOCKLIB_NAMESPACE_END
#endif

#include <string>
#include <vector>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <iostream>

#ifdef __APPLE__
	#include <sys/malloc.h>
#else
	#include <malloc.h>
#endif // __APPLE__

#ifdef _WIN32
	#include <winsock2.h>
	#include <windows.h>
	#include <process.h>
	#include <ws2tcpip.h>
#else // !_WIN32
	#include <sys/socket.h>
	#include <netinet/tcp.h>
	#include <netinet/in.h>
	#include <sys/ioctl.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
	#define SOCKET_ERROR -1
#endif // _WIN32

#if SOCKLIB_TO_LUA
	#ifdef __cplusplus
	extern "C" {
	#endif

	#include "lua.h"
	#include "lualib.h"
	#include "lauxlib.h"

	#ifdef __cplusplus
	}
	#endif
#endif // SOCKLIB_TO_LUA


SOCKLIB_NAMESPACE_BEGIN

typedef unsigned char 		u8_t;
typedef unsigned short 		u16_t;
typedef unsigned int 		u32_t;
typedef unsigned long long 	u64_t;
typedef char		 		i8_t;
typedef short 				i16_t;
typedef int			 		i32_t;
typedef long long 			i64_t;

#if SOCKLIB_TO_LUA

///////////////////////////////////////////////////////////////////////////////
// class LuaHelper
//
// TODO/TOFIX:
//		to manage C++ ptr and LUA gc, maybe luaL_ref()/luaL_unref() is a better choose
//
class LuaHelper
{
public:
	typedef const void Object;
	typedef std::map<Object*, int> Objects;
	
	static void add(Object* obj) {
		_objs[obj] = 1;
	}
	
	static void remove(Object* obj) {
		_objs.erase(obj);
	}
	
	static bool found(Object* obj) {
		return _objs.find(obj) != _objs.end();
	}
	
public:

	template <typename T>
	static int bindAsUdata(lua_State* L, const std::string& name, T* bindObj) {
		T** obj = (T**) lua_newuserdata(L, sizeof(T*));
		*obj = bindObj;
		add(bindObj);
		
	#if LUA_VERSION_NUM == 501
		luaL_getmetatable(L, name.c_str());
		lua_setmetatable(L, -2);
	#else
		luaL_setmetatable(L, name.c_str());
	#endif

		return 1;
	}

	template <typename T>
	static int bindAsTable(lua_State* L, const std::string& name, T* bindObj) {
		lua_newtable(L);
		
		luaL_getmetatable(L, name.c_str());
		lua_setmetatable(L, -2);

		void* obj = lua_newuserdata(L, sizeof(T*));
		*(T**) obj = bindObj;
		add(bindObj);
		
	#if LUA_VERSION_NUM == 501
		luaL_getmetatable(L, name.c_str());
		lua_setmetatable(L, -2);
	#else
		luaL_setmetatable(L, name.c_str());
	#endif
		
		lua_setfield(L, -2, "__cppudata__");

		return 1;
	}
	
	template <typename T, typename... Args>
	static int createAsUdata(lua_State* L, const std::string& name, Args... args) {
		return bindAsUdata<T>(L, name, new T(args...));
	}
	
	template <typename T, typename... Args>
	static int createAsTable(lua_State* L, const std::string& name, Args... args) {
		return bindAsTable<T>(L, name, new T(args...));
	}

public: // default
#if 1 // create C++ class as LUA table
	template <typename T, typename... Args>
	static int create(lua_State* L, const std::string& name, Args... args) {
		return createAsTable<T>(L, name, args...);
	}

	template <typename T>
	static int bind(lua_State* L, const std::string& name, T* bindObj) {
		return bindAsTable<T>(L, name, bindObj);
	}
#else // create C++ class as LUA userdata
	template <typename T, typename... Args>
	static int create(lua_State* L, const std::string& name, Args... args) {
		return createAsUdata<T>(L, name, args...);
	}

	template <typename T>
	static int bind(lua_State* L, const std::string& name, T* bindObj) {
		return bindAsUdata<T>(L, name, bindObj);
	}
#endif

	template <typename T>
	static T* get(lua_State* L, const std::string& name, int idx = 1) {
		if (lua_istable(L, idx)) {
			lua_getfield(L, idx, "__cppudata__");
//			T* _this = *(T**)lua_touserdata(L, -1);
			T* _this = *(T**)luaL_checkudata(L, -1, name.c_str());
			lua_pop(L, 1);
			return _this;
		} else if (lua_isuserdata(L, 1)) {
			return *(T**)luaL_checkudata(L, idx, name.c_str());
		} else {
			luaL_error(L, "LuaHelper::get<>() unknow data");
			return nullptr;
		}
	}

public:
	static void newMetatable(lua_State* L, const std::string& name, const luaL_Reg* reg)
	{
		luaL_newmetatable(L, name.c_str());
		lua_pushvalue(L, -1);
		lua_setfield(L, -2, "__index");

	#if LUA_VERSION_NUM == 501
		luaL_register(L, NULL, reg);
	#else
		luaL_setfuncs(L, reg, 0);
		lua_pop(L, 1);
	#endif
	}

	static int mylua_index_walk(lua_State* L, const char* key);
	static int mylua_index(lua_State* L);

protected:
	static Objects _objs;
};
#endif // SOCKLIB_TO_LUA

///////////////////////////////////////////////////////////////////////////////
// class SockLib
//

class SockLib;
class SockRef;
class SockTcp;
class SockUdp;
class SockBuf;

//typedef std::shared_ptr<SockRef> SockPtr;
typedef SockRef* SockPtr;


///////////////////////////////////////////////////////////////////////////////
// class SockLib
//
class SockLib
{
private:
	SockLib();
	~SockLib();
	
public:
	enum {
		EVT_NONE	= 0,
		EVT_RECV 	= 1 << 0,
		EVT_SEND 	= 1 << 1,
		EVT_CLOSE	= 1 << 2,
		EVT_ERROR	= 1 << 3,
		EVT_ALL		= EVT_RECV | EVT_SEND | EVT_CLOSE,
	};
	
	enum {
		STA_CLOSED,
		STA_CONNECTTING,
		STA_CONNECTED,
		STA_CONNFAILED,
		STA_LISTENED,
		STA_ACCEPTED,
	};
	
	typedef std::map<SockPtr,  int> SockMap;
	
	static bool init();
	static void cleanup();
	
	template <typename T, typename... Args>
	static T* create(Args... args) {
		T* ref = new T(args...);
		if (!ref->create()) {
			delete ref;
			return nullptr;
		}
		return ref;
	}
	
	template <typename... Args>
	static SockTcp* createTcp(Args... args) {
		return create<SockTcp>(args...);
	}
	static SockTcp* createTcp() {
		return create<SockTcp>();
	}
	
	template <typename... Args>
	static SockUdp* createUdp(Args... args) {
		return create<SockUdp>(args...);
	}
	static SockUdp* createUdp() {
		return create<SockUdp>();
	}

	static void destroy(SockPtr ref);
	
	static void add(SockPtr ref, int event);
	static void modify(SockPtr ref, int event);
	static void remove(SockPtr ref);
	static bool found(SockPtr ref);
	
	static void poll(u32_t usec = 10);

	static const char* libName() { return _libName.c_str(); }

protected:
    static int _poll_per_FD_SETSIZE(SockMap::iterator& begin, u32_t usec = 10);
	static void beforePoll();
	static void afterPoll() { dispatch(); }
	static void dispatch();

protected:
	static SockMap _news;
	static SockMap _refs;
	static SockMap _clos;
	static SockMap _dies;

	static fd_set	_fdr, _fdw, _fde;
	static timeval	_tv;

	static std::string	_libName;
	
#if SOCKLIB_TO_LUA
// call @C++
public:
	static int luaRegLib(lua_State* L, const char* libName = SOCKLIB_NAME);
	
	static bool luaAddPath(lua_State* L, const std::string& path);
	static bool luaAddPath(const std::string& path) {
		return luaAddPath(luaState(), path);
	}

	static int luaLoadFile(lua_State* L, const std::string& file, bool protect = true);
	static int luaLoadFile(const std::string& file, bool protect = false) {
		return luaLoadFile(luaState(), file, protect);
	}

	static int luaLoadString(lua_State* L, const std::string& str, bool protect = true);
	static int luaLoadString(const std::string& str, bool protect = false) {
		return luaLoadString(luaState(), str, protect);
	}
	
	static lua_State* luaState() { return _luaState; }

// call @LUA
public:
	static int mylua_tcp(lua_State* L);
	static int mylua_udp(lua_State* L);
	static int mylua_buf(lua_State* L);
	
	static int mylua_poll(lua_State* L);
	
private:
	static lua_State* _luaState;
	
	LuaHelper _luaHelper;
#endif // SOCKLIB_TO_LUA
};

///////////////////////////////////////////////////////////////////////////////
// SockRef
//
class SockRef
{
protected:
	SockRef() {}
	SockRef(const SockRef& r) {}
	SockRef& operator = (const SockRef& r) { return *this; }

public:
	virtual ~SockRef() {}
	
	int fd() { return _fd; }
	
	bool isClosed() {
		return fd() <= 0 || _sockState == SockLib::STA_CLOSED;
	}
	
	virtual int create() = 0;
	virtual void close();

	int careEvent() { return _careEvent; }
	int fireEvent() { return _fireEvent; }
	
	virtual bool careSend() { return true; }
	virtual bool careRecv() { return true; }
	
	int setNonBlock(bool b);
	int setReuseAddr(bool b);
	int setBroadcast(bool b);
	int setRecvTimeout(int seconds);
	int setSendTimeout(int seconds);
	int setRecvBufferSize(int bytes);
	int setSendBufferSize(int bytes);
	int getOption(int optname, char* optval, socklen_t* optlen, int level = SOL_SOCKET);
	int setOption(int optname, const char* optval, socklen_t optlen, int level = SOL_SOCKET);
	int ioctl(unsigned long cmd, unsigned long* arg);
	int getError();
	
public:
	virtual void onConnect(bool ok) {}
	virtual void onAccept() {}
	virtual void onPoll() 	{}
	virtual void onRecv()	= 0;
	virtual void onSend()	= 0;
	virtual void onClose()	= 0;
	
protected:
	int	_careEvent = SockLib::EVT_NONE;
	int _fireEvent = SockLib::EVT_NONE;
	int _sockState = SockLib::STA_CLOSED;
	
	int _fd = -1;
	
	friend SockLib;
	
#if SOCKLIB_TO_LUA
	friend LuaHelper;
#endif
};

///////////////////////////////////////////////////////////////////////////////
// class SockTcp
//
class SockTcp : public SockRef
{
protected:
	SockTcp();
	~SockTcp();
	
public:
	int create();
	
	int connect(const std::string& host, u16_t port);
	int connect(u32_t ip, u16_t port);
	int connect(const sockaddr_in* addr);
	
	int bind(const std::string& ip, u16_t port);
	int bind(u32_t ip, u16_t port);
	int bind(const sockaddr_in* addr);
	int bind(u16_t port) { return bind("", port); }
	
	int listen(int logs = 5);
	
	int accept(sockaddr_in* addr);
	
	void acceptfd(int fd);
	
	int send(const void* buf, u32_t len, int flags = 0);
	int recv(void* buf, u32_t len, int flags = 0);

	void close();

	int doRecv();
	int doSend();

	SockBuf* recvBuf() { return _recvBuf; }
	SockBuf* sendBuf() { return _sendBuf; }

	bool careSend();
	
	int getSockAddr(u32_t* ip, u16_t* port);
	int getSockAddr(std::string& ip, u16_t* port);
	int getSockAddr(sockaddr_in* addr);
	int getPeerAddr(u32_t* ip, u16_t* port);
	int getPeerAddr(std::string& ip, u16_t* port);
	int getPeerAddr(sockaddr_in* addr);

public:
	virtual void onConnect(bool ok);
	virtual void onAccept();
	virtual void onRecv();
	virtual void onSend();
	virtual void onClose();
	virtual void onPoll();

protected:
	SockBuf*	_recvBuf;
	SockBuf*	_sendBuf;
	
	friend SockLib;
	
#if SOCKLIB_TO_LUA
	friend LuaHelper;

// call @C++
public:
	static SockTcp* mylua_this(lua_State* L, int idx = 1);
	
// call @LUA
public:
	static int mylua_connect(lua_State* L);
	static int mylua_listen(lua_State* L);
	static int mylua_accept(lua_State* L);
	static int mylua_close(lua_State* L);
	static int mylua_isclosed(lua_State* L);
	static int mylua_send(lua_State* L);
	static int mylua_recv(lua_State* L);
	static int mylua_inbuf(lua_State* L);
	static int mylua_outbuf(lua_State* L);
	static int mylua_onevent(lua_State* L);
	static int mylua_setopt(lua_State* L);
	static int mylua_sockaddr(lua_State* L);
	static int mylua_peeraddr(lua_State* L);
	static int mylua_index(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_tostring(lua_State* L);
	
private:
	int _mylua_onConnect = -1;
	int _mylua_onRecv = -1;
	int _mylua_onSend = -1;
	int _mylua_onAccept = -1;
	int _mylua_onClose = -1;
	int _mylua_onPoll = -1;
#endif // SOCKLIB_TO_LUA
};

///////////////////////////////////////////////////////////////////////////////
// class SockUdp
//
class SockUdp : public SockRef
{
protected:
	SockUdp();
	~SockUdp();
	
public:
	int create();
	
	// UDP can connect() first then send(), but we don't use it
	
	int sendto(const std::string& host, u16_t port, const void* data, u32_t len);
	int sendto(u32_t ip, u16_t port, const void* data, u32_t len);
	int sendto(const sockaddr_in* addr, const void* data, u32_t len);
	
	int recvfrom(void* data, u32_t len) {
		return recvfrom(data, len, (sockaddr_in*)0);
	}
	int recvfrom(void* data, u32_t len, u32_t* ip, u16_t* port);
	int recvfrom(void* data, u32_t len, std::string& ip, u16_t* port);
	int recvfrom(void* data, u32_t len, sockaddr_in* addr);
	
public:
	virtual void onRecv();
	virtual void onSend();
	virtual void onClose();
	virtual void onPoll();

private:
	
	friend SockLib;

#if SOCKLIB_TO_LUA
	friend LuaHelper;

// call @C++
public:
	static SockUdp* mylua_this(lua_State* L, int idx = 1);

// call @LUA
public:
	static int mylua_sendto(lua_State* L);
	static int mylua_recvfrom(lua_State* L);
	static int mylua_close(lua_State* L);
	static int mylua_onevent(lua_State* L);
	static int mylua_setopt(lua_State* L);
	static int mylua_index(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_tostring(lua_State* L);
	
private:
	int _mylua_onRecv = -1;
	int _mylua_onSend = -1;
	int _mylua_onClose = -1;
	int _mylua_onPoll = -1;

#endif // SOCKLIB_TO_LUA
};

///////////////////////////////////////////////////////////////////////////////
// class SockBuf
//
class SockBuf
{
public:
	SockBuf();
	~SockBuf();
	
	SockBuf(SockBuf&& r) {
		_ptr = r._ptr;
		_max = r._max;
		_pos_r = r._pos_r;
		_pos_w = r._pos_w;
		r._ptr = 0;
		r._max = r._pos_r = r._pos_w = 0;
	}
	
private:
	SockBuf(const SockBuf& r);
	SockBuf& operator = (const SockBuf& r);
	
public:
	/// only for read
	u8_t*	pos() const { return _ptr + _pos_r;	}
	u32_t	len() const { return _pos_w - _pos_r;	}

	int write(const void* data, u32_t bytes);
	int read(void* data, u32_t bytes);
	int peek(void* data, u32_t bytes);
	void reset();
	
	SockBuf& skip(u32_t bytes) {
		if (bytes > len())
			bytes = len();
		_pos_r += bytes;
		return *this;
	}
	
	SockBuf& discard(u32_t bytes);
	
	int wbuf(const SockBuf& buf, u32_t len = 0) {
		u32_t _le = buf.len();
		if (_le) {
			if (!len) len = _le;
			else if (len > _le) len = _le;
			return write(buf.pos(), len);
		}
		return 0;
	}
	
	int rbuf(SockBuf& buf, u32_t len) {
		int r = pbuf(buf, 0, len);
		_pos_r += r;
		return r;
	}
	
	int pbuf(SockBuf& buf, u32_t from, u32_t len) {
		u32_t _le = this->len();
		if ((from + len) < _le &&
			len == buf.write(this->pos() + from, len)) {
			return len;
		}
		return 0;
	}
	
	///////////////////////////////////////////////////
	// write

	SockBuf& w(const void* v, u32_t bytes) {
		write(v, bytes);
		return *this;
	}
	
	SockBuf& wl(const void* v, u32_t bytes) {
		return w32(bytes).w(v, bytes);
	}
	
	SockBuf& ws(const char* s) {
		if (s)
			return w(s, (u32_t)strlen(s) + 1);
		else
			return w8(0);
	}

	SockBuf& wsl(const char* s) {
		if (s) {
			u16_t bytes = (u16_t)strlen(s);
			return w16(bytes).w(s, bytes);
		} else {
			return w16(0);
		}
	}

	SockBuf& w8(u8_t v) {
		return w(&v, 1);
	}
	
	SockBuf& w16(u16_t v) {
		v = htons(v);
		return w(&v, sizeof(v));
	}
	
	SockBuf& w32(u32_t v) {
		v = htonl(v);
		return w(&v, sizeof(v));
	}
	
	SockBuf& w64(u64_t v) {
		v = htonll(v);
		return w(&v, sizeof(v));
	}
	
	///////////////////////////////////////////////////
	// read
	
	u8_t* r(u32_t bytes) {
		if (bytes > len())
			return 0;
		
		u8_t* buf = _ptr + _pos_r;
		_pos_r += bytes;
		
		return buf;
	}
	
	u8_t* rl(u32_t& bytes) {
		if (len() >= sizeof(u32_t)) {
			bytes = p32();
			if (len() >= (bytes + sizeof(u32_t))) {
				_pos_r += sizeof(u32_t) + bytes;
				return pos() - bytes;
			}
		}
		return 0;
	}
	
	u8_t r8() {
		u8_t v = 0;
		if (len() >= sizeof(v)) {
			v = pos()[0];
			_pos_r += sizeof(v);
		}
		return v;
	}
	
	u16_t r16() {
		u16_t v = 0;
		if (len() >= sizeof(v)) {
			memcpy(&v, pos(), sizeof(v));
			_pos_r += sizeof(v);
			v = ntohs(v);
		}
		return v;
	}
	
	u32_t r32() {
		u32_t v = 0;
		if (len() >= sizeof(v)) {
			memcpy(&v, pos(), sizeof(v));
			_pos_r += sizeof(v);
			v = ntohl(v);
		}
		return v;
	}
	
	u64_t r64() {
		u64_t v = 0;
		if (len() >= sizeof(v)) {
			memcpy(&v, pos(), sizeof(v));
			_pos_r += sizeof(v);
			v = ntohll(v);
		}
		return v;
	}
	
	//
	const char*	rs() {
		char* beg = (char*)pos();
		char* p = beg;
		u32_t l = len();

		if (!p || !l) return "";

		while (l && *p) {
			p++; l--;
		}
		if (*p == 0) {
			_pos_r += p - beg;
			if (len()) _pos_r += 1;
			return beg;
		}
		return "";
	}
	
	const char*	rsl() {
		if (len() >= sizeof(u16_t)) {
			u16_t bytes = p16();
			if (len() >= (bytes + sizeof(u16_t))) {
				_pos_r += sizeof(u16_t) + bytes;
				return (char*)pos() - bytes;
			}
		}
		return 0;
	}

	///////////////////////////////////////////////////
	// peek
	
	u8_t* p(u32_t bytes) {
		return bytes > len() ? 0 : pos();
	}
	
	u8_t* pl(u32_t& bytes) {
		if (len() >= sizeof(u32_t)) {
			bytes = p32();
			if (len() >= (bytes + sizeof(u32_t))) {
				return pos() + sizeof(u32_t);
			}
		}
		return 0;
	}
	
	u8_t p8() {
		u8_t v = 0;
		if (len() >= sizeof(v)) {
			v = pos()[0];
		}
		return v;
	}
	
	u16_t p16() {
		u16_t v = 0;
		if (len() >= sizeof(v)) {
			memcpy(&v, pos(), sizeof(v));
			v = ntohs(v);
		}
		return v;
	}
	
	u32_t p32() {
		u32_t v = 0;
		if (len() >= sizeof(v)) {
			memcpy(&v, pos(), sizeof(v));
			v = ntohl(v);
		}
		return v;
	}
	
	u64_t p64() {
		u64_t v = 0;
		if (len() >= sizeof(v)) {
			memcpy(&v, pos(), sizeof(v));
			v = ntohll(v);
		}
		return v;
	}
	
	const char*	ps() {
		char* p = (char*)pos();
		u32_t l = len();

		if (!p || !l) return 0;

		while (l && *p) {
			p++; l--;
		}
		if (*p == 0) {
			return (char*)pos();
		}
		return 0;
	}
	
	const char*	psl() {
		if (len() >= sizeof(u16_t)) {
			u16_t bytes = p16();
			if (len() >= (bytes + sizeof(u16_t))) {
				return (char*)pos() + sizeof(u16_t);
			}
		}
		return 0;
	}

protected:
	u8_t*	_ptr;
	u32_t	_max;		// alloced
	u32_t	_pos_w;		// write
	u32_t	_pos_r;		// read
	
	friend SockLib;

#if SOCKLIB_TO_LUA
	friend LuaHelper;

// call @C++
public:
	static SockBuf* mylua_this(lua_State* L, int idx = 1);

// call @LUA
public:
	static int mylua_reset(lua_State* L);
	static int mylua_skip(lua_State* L);
	static int mylua_discard(lua_State* L);
	static int mylua_buffer(lua_State* L);
	static int mylua_length(lua_State* L);
	static int mylua_index(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_tostring(lua_State* L);
	
	static int mylua_w(lua_State* L);
	static int mylua_wl(lua_State* L);
	static int mylua_ws(lua_State* L);
	static int mylua_wsl(lua_State* L);
	static int mylua_w8(lua_State* L);
	static int mylua_w16(lua_State* L);
	static int mylua_w32(lua_State* L);
	static int mylua_w64(lua_State* L);

	static int mylua_r(lua_State* L);
	static int mylua_rl(lua_State* L);
	static int mylua_rs(lua_State* L);
	static int mylua_rsl(lua_State* L);
	static int mylua_r8(lua_State* L);
	static int mylua_r16(lua_State* L);
	static int mylua_r32(lua_State* L);
	static int mylua_r64(lua_State* L);

	static int mylua_p(lua_State* L);
	static int mylua_pl(lua_State* L);
	static int mylua_ps(lua_State* L);
	static int mylua_psl(lua_State* L);
	static int mylua_p8(lua_State* L);
	static int mylua_p16(lua_State* L);
	static int mylua_p32(lua_State* L);
	static int mylua_p64(lua_State* L);

	static int mylua_sub(lua_State* L);
#endif // SOCKLIB_TO_LUA
};


#if SOCKLIB_ALG
///////////////////////////////////////////////////////////////////////////////
// RC4
//
// RC4 codes write by someone I don't know.
//
/* 
 ********************************************************************** 
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. ** 
 **                                                                  ** 
 ** License to copy and use this software is granted provided that   ** 
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     ** 
 ** Digest Algorithm" in all material mentioning or referencing this ** 
 ** software or this function.                                       ** 
 **                                                                  ** 
 ** License is also granted to make and use derivative works         ** 
 ** provided that such works are identified as "derived from the RSA ** 
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         ** 
 ** material mentioning or referencing the derived work.             ** 
 **                                                                  ** 
 ** RSA Data Security, Inc. makes no representations concerning      ** 
 ** either the merchantability of this software or the suitability   ** 
 ** of this software for any particular purpose.  It is provided "as ** 
 ** is" without express or implied warranty of any kind.             ** 
 **                                                                  ** 
 ** These notices must be retained in any copies of any part of this ** 
 ** documentation and/or software.                                   ** 
 ********************************************************************** 
 */
class RC4
{
public:
	RC4() : _i(0), _j(0) {}
	RC4(const u8_t* key, u32_t size) : _i(0), _j(0) {
		setKey(key, size);
	}

	void setKey(const u8_t* key, u32_t size) {
		u32_t t;
		// initialize state
		for (t = 0; t < 256; t++)
			_s[t] = t;

		_j = 0;
		for (t = 0; t < 256; t++) {
			_j = (_j + _s[t] + key[t % size]) & 0xff;
			rc4_swap(_s[t], _s[_j]);
		}

		_i = _j = 0;
	}
	
	void process(const u8_t* in, u8_t* out, u32_t size) {
		for (u32_t k = 0; k < size; k++)
			out[k] = process(in[k]);
	}

	u8_t process(u8_t b) {
		_i = (_i + 1) & 0xff;
		_j = (_j + _s[_i]) & 0xff;
		rc4_swap(_s[_i], _s[_j]);
		u8_t t = _s[ (_s[_i] + _s[_j]) & 0xff];
		return t ^ b;
	}

	static void build(const u8_t* key, u32_t keySize,
		const u8_t* inDat, u8_t* outDat, u32_t datSize) {
		RC4 rc4(key, keySize);
		rc4.process(inDat, outDat, datSize);
	}

	static inline void rc4_swap(u8_t& a, u8_t& b) {
		u8_t t = a; a = b; b = t;
	}
	
private:
	u8_t _i, _j;
	u8_t _s[256];
	
#if SOCKLIB_TO_LUA
// call @LUA
public:
	static int mylua_setkey(lua_State* L);
	static int mylua_process(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_tostring(lua_State* L);
#endif // SOCKLIB_TO_LUA
};

static inline void RC4_build(const void* key, u32_t keySize,
		const void* inDat, void* outDat, u32_t datSize)
{
	RC4::build((const u8_t*)key, keySize, (const u8_t*)inDat, (u8_t*)outDat, datSize);
}

///////////////////////////////////////////////////////////////////////////////
// class CRC32
//
u32_t CRC32_build(const void* data, u32_t len, u32_t crc = 0);

///////////////////////////////////////////////////////////////////////////////
// class MD5
//
/* 
 ********************************************************************** 
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. ** 
 **                                                                  ** 
 ** License to copy and use this software is granted provided that   ** 
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     ** 
 ** Digest Algorithm" in all material mentioning or referencing this ** 
 ** software or this function.                                       ** 
 **                                                                  ** 
 ** License is also granted to make and use derivative works         ** 
 ** provided that such works are identified as "derived from the RSA ** 
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         ** 
 ** material mentioning or referencing the derived work.             ** 
 **                                                                  ** 
 ** RSA Data Security, Inc. makes no representations concerning      ** 
 ** either the merchantability of this software or the suitability   ** 
 ** of this software for any particular purpose.  It is provided "as ** 
 ** is" without express or implied warranty of any kind.             ** 
 **                                                                  ** 
 ** These notices must be retained in any copies of any part of this ** 
 ** documentation and/or software.                                   ** 
 ********************************************************************** 
 */
class MD5
{
public:
	MD5() { init(); }

	void init();
	void update(const u8_t* data, u32_t len);
	void final(u8_t digest[16]);
	
	static void build(u8_t hash[16], const void* data, u32_t len);

private:	
	u32_t	_state[4];
	u32_t	_count[2];
	u8_t	_buffer[64];
	
#if SOCKLIB_TO_LUA
// call @LUA
public:
	static int mylua_init(lua_State* L);
	static int mylua_update(lua_State* L);
	static int mylua_final(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_tostring(lua_State* L);
#endif // SOCKLIB_TO_LUA
};

static inline void MD5_build(u8_t hash[16], const void* data, u32_t len)
{
	MD5::build(hash, data, len);
}

///////////////////////////////////////////////////////////////////////////////
// class SHA1
//
/* 
 ********************************************************************** 
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. ** 
 **                                                                  ** 
 ** License to copy and use this software is granted provided that   ** 
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     ** 
 ** Digest Algorithm" in all material mentioning or referencing this ** 
 ** software or this function.                                       ** 
 **                                                                  ** 
 ** License is also granted to make and use derivative works         ** 
 ** provided that such works are identified as "derived from the RSA ** 
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         ** 
 ** material mentioning or referencing the derived work.             ** 
 **                                                                  ** 
 ** RSA Data Security, Inc. makes no representations concerning      ** 
 ** either the merchantability of this software or the suitability   ** 
 ** of this software for any particular purpose.  It is provided "as ** 
 ** is" without express or implied warranty of any kind.             ** 
 **                                                                  ** 
 ** These notices must be retained in any copies of any part of this ** 
 ** documentation and/or software.                                   ** 
 ********************************************************************** 
 */
class SHA1
{
public:
	SHA1() { init(); }

	void init();
	void update(const u8_t* data, u32_t len);
	void final(u8_t digest[20]);
	
	static void build(u8_t hash[20], const void* data, u32_t len);

private:
	u32_t	_state[5];
	u32_t	_count[2];
	u8_t	_buffer[64];
	
#if SOCKLIB_TO_LUA
// call @LUA
public:
	static int mylua_init(lua_State* L);
	static int mylua_update(lua_State* L);
	static int mylua_final(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_tostring(lua_State* L);
#endif // SOCKLIB_TO_LUA
};

static inline void SHA1_build(u8_t hash[20], const void* data, u32_t len)
{
	SHA1::build(hash, data, len);
}

///////////////////////////////////////////////////////////////////////////////
// class Base64
//
std::string Base64_encode(const void* buf, u32_t len);
std::string Base64_decode(const char* sz, u32_t len = 0);

#endif // SOCKLIB_ALG

///////////////////////////////////////////////////////////////////////////////
// class Timer
//
class Timer {
public:
	typedef std::function<bool(Timer& tmr)> Callback;
	typedef std::map<u64_t, Timer> TimerMap;
	typedef std::map<u64_t, int> TmrIdMap;
	
	static u64_t add(Timer& tmr);
	static void remove(u64_t tmrId);
	static void poll();
	
	void	onTick(u64_t tick);
	
	void 	cancel() { remove(_timerId); }
	
	u64_t	timerId() { return _timerId; }
	u64_t	interval() { return _interval; }
	i64_t	curLoops() { return _curLoops; }
	i64_t	maxLoops() { return _maxLoops; }
	
private:
	static TimerMap _refs;
	static TimerMap _news;
	static TmrIdMap _dies;
	
#if SOCKLIB_TO_LUA
	static TmrIdMap _mylua_refs;
#endif

private:
	u64_t 	_timerId = 0;
	u64_t	_curTick = 0;
	u64_t	_interval = 0;
	i64_t   _curLoops = 0;
	i64_t	_maxLoops = 0;
	Callback _callback = nullptr;
	
#if SOCKLIB_TO_LUA
	int 	_mylua_ref = -1;
#endif

	friend class Util;
};

///////////////////////////////////////////////////////////////////////////////
// class Util
//
class Util
{
public:
	static u64_t 		tick();
	
	static std::string	ipn2s(u32_t ip);
	static u32_t 		ips2n(const std::string& addr);
	
	// probe from cache
	static u32_t 		ipprobe(const std::string& addr);

	static std::string	urlenc(const std::string& url);
	static std::string	urldec(const std::string& url);

	static u64_t setTimer(u64_t delayMsec, const Timer::Callback& func, i64_t maxLoops = -1);
	static void	 delTimer(u64_t tmrId);
	
	static void poll();
	
	static void addr2ips(const sockaddr_in* addr, std::string& ip, u16_t* port);
	static void addr2ipn(const sockaddr_in* addr, u32_t* ip, u16_t* port);
	static void ips2addr(const std::string& ip, u16_t port, sockaddr_in* addr);
	static void ipn2addr(u32_t ip, u16_t port, sockaddr_in* addr);
	
private:
	typedef std::map<const std::string, u32_t> IPCache;
	static IPCache _ipcache;
	static std::mutex _ipmutex;
	
	struct AutoMutex {
		AutoMutex(std::mutex& mutex) : _mutex(mutex) {
			_mutex.lock();
		}
		~AutoMutex() {
			_mutex.unlock();
		}
		
	private:
		AutoMutex(const AutoMutex& r);
		AutoMutex& operator = (const AutoMutex& r);
		
	private:
		std::mutex& _mutex;
	};

#if SOCKLIB_TO_LUA
	static bool _onTimerCallback(Timer& tmr);
	
// call @LUA
public:
	#if SOCKLIB_ALG
	static int mylua_crc32(lua_State* L);
	static int mylua_rc4(lua_State* L);
	static int mylua_md5(lua_State* L);
	static int mylua_sha1(lua_State* L);
	static int mylua_b64enc(lua_State* L);
	static int mylua_b64dec(lua_State* L);
	#endif // SOCKLIB_ALG

	static int mylua_u32op(lua_State* L);

	static int mylua_tick(lua_State* L);

	static int mylua_urlenc(lua_State* L);
	static int mylua_urldec(lua_State* L);

	static int mylua_ips2n(lua_State* L);
	static int mylua_ipn2s(lua_State* L);

	static int mylua_ipprobe(lua_State* L);

	static int mylua_settimer(lua_State* L);
	static int mylua_deltimer(lua_State* L);
	
	static int mylua_htons(lua_State* L);
	static int mylua_ntohs(lua_State* L);
	static int mylua_htonl(lua_State* L);
	static int mylua_ntohl(lua_State* L);
	static int mylua_htonll(lua_State* L);
	static int mylua_ntohll(lua_State* L);
#endif // SOCKLIB_TO_LUA
};

SOCKLIB_NAMESPACE_END

#endif // !__SOCKLIB_H__
