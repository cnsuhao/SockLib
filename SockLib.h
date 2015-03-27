//
//  SockLib.h
//
//  Created by liangX<liangx.cn@qq.com> on 15/3/25.
//  Copyright (c) 2015. All rights reserved.
//

#ifndef __SOCKLIB_H__
#define __SOCKLIB_H__

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

// lib name in LUA
// you can change this name
#ifndef SOCKLIB_NAME
#define SOCKLIB_NAME		"socklib"
#endif

// use a namespace(cpp effected only)?
// you can change the name of namespace
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
	#pragma comment(lib,"ws2_32.lib")
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

#if SOCKLIB_TO_LUA

///////////////////////////////////////////////////////////////////////////////
// class LuaHelper
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
	static void debugScriptFile(lua_State* L, const std::string& file)
	{
		luaL_loadfile(L, file.c_str());
		lua_call(L, 0, LUA_MULTRET);
	}
	
public:

	template <typename T>
	static int bind(lua_State* L, const std::string& name, T* bindObj) {
		T** obj = (T**) lua_newuserdata(L, sizeof(T*));
		*obj = bindObj;
		
	#if LUA_VERSION_NUM == 501
		luaL_getmetatable(L, name.c_str());
		lua_setmetatable(L, -2);
	#else
		luaL_setmetatable(L, name.c_str());
	#endif

		return 1;
	}
	
	template <typename T, typename... Args>
	static int create(lua_State* L, const std::string& name, Args... args) {
		T* p = new T(args...);
		add(p);
		return bind<T>(L, name, p);
	}

	template <typename T>
	static T* get(lua_State* L, const std::string& name, int idx = 1) {
		return *(T**)luaL_checkudata(L, idx, name.c_str());
	}

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

#if SOCKLIB_ALG
///////////////////////////////////////////////////////////////////////////////
// RC4
//
// RC4 codes write by someone I don't know.
//
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
public:
	static int mylua_setKey(lua_State* L);
	static int mylua_process(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_toString(lua_State* L);
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
class MD5
{
public:
	static void build(u8_t hash[16], const void* data, u32_t len);

	void init();
	void update(const u8_t* data, u32_t len);
	void final(u8_t digest[16]);

private:	
	u32_t	_state[4];
	u32_t	_count[2];
	u8_t	_buffer[64];
	
#if SOCKLIB_TO_LUA
public:
	static int mylua_init(lua_State* L);
	static int mylua_update(lua_State* L);
	static int mylua_final(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_toString(lua_State* L);
#endif // SOCKLIB_TO_LUA
};

static inline void MD5_build(u8_t hash[16], const void* data, u32_t len)
{
	MD5::build(hash, data, len);
}

///////////////////////////////////////////////////////////////////////////////
// class SHA1
//
class SHA1
{
public:
	static void build(u8_t hash[20], const void* data, u32_t len);

	void init();
	void update(const u8_t* data, u32_t len);
	void final(u8_t digest[20]);
	
private:
	u32_t	_state[5];
	u32_t	_count[2];
	u8_t	_buffer[64];
	
#if SOCKLIB_TO_LUA
public:
	static int mylua_init(lua_State* L);
	static int mylua_update(lua_State* L);
	static int mylua_final(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_toString(lua_State* L);
#endif // SOCKLIB_TO_LUA
};

static inline void SHA1_build(u8_t hash[20], const void* data, u32_t len)
{
	SHA1::build(hash, data, len);
}

///////////////////////////////////////////////////////////////////////////////
// class Base64
//
class Base64
{
};

///////////////////////////////////////////////////////////////////////////////
// class Util
//
class Util
{
};

#endif // SOCKLIB_ALG

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
		EVT_RECV 	= 1 << 1,
		EVT_SEND 	= 1 << 2,
		EVT_CLOSE	= 1 << 3,
		EVT_ERROR	= 1 << 4,
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
	
	template <typename... Args>
	static SockTcp* createUdp(Args... args) {
		return create<SockUdp>(args...);
	}

	static void destroy(SockPtr ref);
	
	static void add(SockPtr ref, int event);
	static void modify(SockPtr ref, int event);
	static void remove(SockPtr ref);
	static bool found(SockPtr ref);
	
	static void poll(u32_t usec = 10);

protected:
    static int _poll_per_FD_SETSIZE(SockMap::iterator begin, SockMap::iterator end, u32_t usec = 10);
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
	
#if SOCKLIB_TO_LUA
public:
	static const char* libName() { return _libName.c_str(); }

	static int mylua_regAs(lua_State* L, const char* libName);
	static int mylua_reg(lua_State* L) { return mylua_regAs(L, SOCKLIB_NAME); }
	
	static int mylua_tcp(lua_State* L);
	static int mylua_udp(lua_State* L);
	static int mylua_buf(lua_State* L);
	
	static int mylua_poll(lua_State* L);
	
	#if SOCKLIB_ALG
	static int mylua_u32op(lua_State* L);
	static int mylua_crc32(lua_State* L);
	static int mylua_rc4(lua_State* L);
	static int mylua_md5(lua_State* L);
	static int mylua_sha1(lua_State* L);
	static int mylua_b64enc(lua_State* L);
	static int mylua_b64dec(lua_State* L);
	#endif // SOCKLIB_ALG

	static lua_State* luaState() { return _luaState; }
	
private:
	static std::string	_libName;
	static lua_State*	_luaState;
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
	virtual void onRecv()	= 0;
	virtual void onSend()	= 0;
	virtual void onClose()	= 0;
	
protected:
	int	_careEvent = SockLib::EVT_NONE;
	int _fireEvent = SockLib::EVT_NONE;
	int _sockState = SockLib::STA_CLOSED;
	
	int _fd = -1;
	
	friend SockLib;
	friend LuaHelper;
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

	int send(const void* buf, u32_t len, int flags = 0);
	int recv(void* buf, u32_t len, int flags = 0);
	
	int bind(const std::string& ip, u16_t port);
	int bind(u16_t port) { return bind("", port); }
	int listen(int logs = 5);
	
	int accept(SockTcp* client);
	
	void close();

	int doRecv();
	int doSend();

	SockBuf* recvBuf() { return _recvBuf; }
	SockBuf* sendBuf() { return _sendBuf; }

public:
	virtual void onConnect(bool ok);
	virtual void onAccept();
	virtual void onRecv();
	virtual void onSend();
	virtual void onClose();

protected:
	SockBuf*	_recvBuf;
	SockBuf*	_sendBuf;
	
	friend SockLib;
	friend LuaHelper;
	
#if SOCKLIB_TO_LUA
public:
	static SockTcp* mylua_this(lua_State* L, int idx = 1);

	static int mylua_connect(lua_State* L);
	static int mylua_listen(lua_State* L);
	static int mylua_accept(lua_State* L);
	static int mylua_close(lua_State* L);
	static int mylua_send(lua_State* L);
	static int mylua_recv(lua_State* L);
	static int mylua_recvBuf(lua_State* L);
	static int mylua_sendBuf(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_toString(lua_State* L);
	static int mylua_onEvent(lua_State* L);
	
private:
	int _mylua_onConnect = 0;
	int _mylua_onRecv = 0;
	int _mylua_onSend = 0;
	int _mylua_onAccept = 0;
	int _mylua_onClose = 0;
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
	
	int sendTo(const std::string& host, u16_t port, const char* data, u32_t len);
	int recvFrom();
	
public:
	virtual void onRecv();
	virtual void onSend();
	virtual void onClose();

private:
	
	friend SockLib;
	friend LuaHelper;


#if SOCKLIB_TO_LUA
public:
	static SockUdp* mylua_this(lua_State* L, int idx = 1);

	static int mylua_sendTo(lua_State* L);
	static int mylua_recvFrom(lua_State* L);
	static int mylua_close(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_toString(lua_State* L);
	
private:
	int _mylua_onRecv = 0;
	int _mylua_onSend = 0;
	int _mylua_onClose = 0;

#endif // SOCKLIB_TO_LUA
};

///////////////////////////////////////////////////////////////////////////////
// class SockBuf
//
#define SOCKBUF_BLOCK_SIZE	(1024 * 4)

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

		if ((from + len) >= _le)
			return 0;

		if (len == buf.write(this->pos() + from, len)) {
			_pos_r += len;
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
				_pos_r += sizeof(u32_t);
				
				u8_t* buf = _ptr + _pos_r;
				_pos_r += bytes;
				
				return buf;
			}
		}
		return 0;
	}
	
	u8_t r8() {
		if (sizeof(u8_t) > len())
			return 0;

		u8_t v = p8();
		_pos_r += sizeof(v);
		return v;
	}
	
	u16_t r16() {
		if (sizeof(u16_t) > len())
			return 0;

		u16_t v = p16();
		_pos_r += sizeof(v);
		return v;
	}
	
	u32_t r32() {
		if (sizeof(u32_t) > len())
			return 0;

		u32_t v = p32();
		_pos_r += sizeof(v);
		return v;
	}
	
	u64_t r64() {
		if (sizeof(u64_t) > len())
			return 0;

		u64_t v = p64();
		_pos_r += sizeof(v);
		return v;
	}
	
	//
	const char*	rs() {
		char* beg = (char*)pos();
		char* p = beg;
		u32_t l = len();

		if (!p || !l) return 0;

		while (l && *p) {
			p++; l--;
		}
		if (*p == 0) {
			_pos_r += p - beg + 1;
			return beg;
		}
		return 0;
	}
	
	const char*	rsl() {
		if (len() >= sizeof(u16_t)) {
			u16_t bytes = p16();
			if (len() >= (bytes + sizeof(u16_t))) {
				_pos_r += sizeof(u16_t);
				
				u8_t* buf = _ptr + _pos_r;
				_pos_r += bytes;
				
				return (char*)buf;
			}
		}
		return 0;
	}
	
	SockBuf& skip(u32_t bytes) {
		if (bytes > len())
			bytes = len();
		_pos_r += bytes;
		return *this;
	}
	
	SockBuf& discard(u32_t bytes) {
		if (bytes > len())
			bytes = len();
		_pos_r += bytes;

		if (_pos_r >= _pos_w) {
			_pos_w = 0;
			_pos_r = 0;
			_ptr[0] = 0;
			
			if (_max > SOCKBUF_BLOCK_SIZE) {
				free(_ptr);
				_ptr = (u8_t*) malloc(SOCKBUF_BLOCK_SIZE);
				_max = SOCKBUF_BLOCK_SIZE;
			}
		}
		return *this;
	}

	///////////////////////////////////////////////////
	// peek
	
	u8_t* p(u32_t bytes) {
		if (bytes > len())
			return 0;
		
		u8_t* buf = _ptr + _pos_r;
		
		return buf;
	}
	
	u8_t* pl(u32_t& bytes) {
		if (len() >= sizeof(u32_t)) {
			bytes = p32();
			if (len() >= (bytes + sizeof(u32_t))) {
				_pos_r += sizeof(u32_t);
				
				u8_t* buf = _ptr + _pos_r;
				
				return buf;
			}
		}
		return 0;
	}
	
	u8_t p8() {
		u8_t v = 0;
		memcpy(&v, pos(), sizeof(v));
		return v;
	}
	
	u16_t p16() {
		u16_t v = 0;
		memcpy(&v, pos(), sizeof(v));
		return ntohs(v);
	}
	u32_t p32() {
		u32_t v = 0;
		memcpy(&v, pos(), sizeof(v));
		return ntohl(v);
	}
	u64_t p64() {
		u64_t v = 0;
		memcpy(&v, pos(), sizeof(v));
		return ntohll(v);
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
				_pos_r += sizeof(u16_t);
				
				u8_t* buf = _ptr + _pos_r;
				
				return (char*)buf;
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
	friend LuaHelper;


#if SOCKLIB_TO_LUA
public:
	static SockBuf* mylua_this(lua_State* L, int idx = 1);

	static int mylua_reset(lua_State* L);
	static int mylua_skip(lua_State* L);
	static int mylua_discard(lua_State* L);
	static int mylua_buffer(lua_State* L);
	static int mylua_length(lua_State* L);
	static int mylua_gc(lua_State* L);
	static int mylua_toString(lua_State* L);
	
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

SOCKLIB_NAMESPACE_END

#endif // !__SOCKLIB_H__
