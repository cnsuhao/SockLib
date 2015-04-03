local util = socklib.util

local function test_util_md5()
	-- 1 a md5 function
	print( util.md5("hello") )

	-- 2 a md5 obj
	print( util.md5():update("hello"):final() )

	-- 3 more step update data and data
	print( util.md5():update("he"):update("llo"):final() )

	-- 4 socklib.buf is a byte stream
	local buf = socklib.buf():w("hello")
	print( util.md5(buf) )
	print( util.md5():update(buf):final() )

	-- 5 out format: socklib.FMT.*
	local bbb = util.md5():update("hello"):final(socklib.FMT.BUF)
	print( bbb )
end

local function test_util_sha1()
	-- 1 a sha1 function
	print( util.sha1("hello") )

	-- 2 a sha1 obj
	print( util.sha1():update("hello"):final() )

	-- 3 more step update data and data
	print( util.sha1():update("he"):update("llo"):final() )

	-- 4 socklib.buf is a byte stream
	local buf = socklib.buf():w("hello")
	print( util.sha1(buf) )
	print( util.sha1():update(buf):final() )

	-- 5 out format: socklib.FMT.*
	local bbb = util.sha1():update("hello"):final(socklib.FMT.HEX)
	print( bbb )
end

local function test_util_rc4()
	-- 1 a rc4 function
	print( util.rc4("key_aa", "data_bb") )

	-- 2 a rc4 obj
	print( util.rc4():setKey("key_aa"):process("data_bb") )

	-- 3 use fun: rc4(rc4_data) = originally data
	local buf = util.rc4("key_aa", "data_bb")
	print (util.rc4("key_aa", buf):ps() )

	-- 4 use obj: rc4(rc4_data) = originally data
	local buf = util.rc4():setKey("key_aa"):process("data_bb")
	print (util.rc4():setKey("key_aa"):process(buf):ps() )
end

local function test_util_crc32()
	-- util.crc32(a string or a lightudata or a socklib.buf, optinal len, optinal salk)

	print( util.crc32("haha") )
	print( util.crc32("haha", 4) )
	print( util.crc32("haha", 4, 0) )
	print( util.crc32("haha", 4, 123) )

	-- socklib.buf is a byte stream
	print( util.crc32( socklib.buf():w("haha") ) )
end

local function test_util_base64()
	local e = util.b64enc("haha")
	local d = util.b64dec(e)

	print(e)
	print(d)
end

local function test_util_u32op()
	-- 2 args = socklib.util.u32op("opt_str", num)
	print( util.u32op("!", 123) )
	print( util.u32op("~", 123) )

	-- 3 args = socklib.util.u32op(num1, "opt_str", num2)
	print( util.u32op(123, "<<", 2) )
	print( util.u32op(123, "&", 2) )
	print( util.u32op(123, "|= ~", 2) )
end

-- tmrId = socklib.util.setTimer(delay_msec, function(id, curloops, maxloops) end, max_loops = -1)
-- socklib.util.delTimer(tmrId)
function test_util_timer()
	local delay_msec = 1000
	local max_loops = 5

	util.setTimer(delay_msec, function(tmrId, curLoops)
		print("timer5loops1 id = " .. tostring(tmrId) .. ", curLoops = " .. tostring(curLoops))
	end, max_loops)

	util.setTimer(1000, function(id, c, m)
		print("timer5loops2 id = " .. tostring(id) .. ", curLoops = " .. tostring(c) .. ", maxLoops = " .. tostring(m))
		return c < 5 -- return false to stop
	end)

	util.setTimer(delay_msec, function()
		print("timer10loops1")
	end, 10)

	local tmrId = util.setTimer(1000, function(tmrId, curLoops, maxLoops)
		print("timer_todel id = " .. tostring(tmrId) .. ", curLoops = " .. tostring(curLoops) .. ", maxLoops = " .. tostring(maxLoops))
	end, -1)

	util.delTimer(tmrId)
end

-- util.ips2n() is blocking
-- util.ipprobe() is not blocking
local function test_util_ipprobe()
	local host = "www.lua.org"
	local ip = util.ipprobe(host)
	
	local function onGot(b)
		if b then
			print(host .. " = " .. util.ipn2s(ip))
			-- continue to do something
		else
			print("can't get ip for " .. host)
		end	
	end
	
	if ip > 0 then
		onGot(true)
	else -- create a timer to try
		util.setTimer(1000, function(tmrId, curLoops)
			print("querying " .. host .. "...")
			ip = util.ipprobe(host)
			if ip > 0 then
				onGot(true)
				return false -- to stop timer
			elseif curLoops >= 10 then
				print("too many times to try")
				onGot(false)
				return false -- to stop timer
			end
		end)
	end
end

local function test_util_other()
	print( util.tick() )
	print( util.urlenc("http://aa.bb.cc/dd ee.asp") )
	print( util.urldec(util.urlenc("http://aa.bb.cc/dd ee.asp")) )
	print( util.ips2n("192.168.0.1") )
	print( util.ipn2s(util.ips2n("192.168.0.1")) )
	print( util.ntohs(util.htons(12)) )
	print( util.ntohl(util.htonl(12)) )
	print( util.ntohll(util.htonll(12)) )
end

-- socklib.buf is a byte stream
-- write:  w() wl() ws() wsl() w8() w16() ....
-- read:   r() rl() rs() rsl() r8() r16() ....
-- peek:   p() pl() ps() psl() p8() p16() ....
-- skip/discard:   skip() == discard()
-- property: buf len md5 sha1 hex b64/base64 crc/crc32
local function test_buf()
	local tmp = socklib.buf():ws("tmp")
	local buf = socklib.buf();
	print( buf:w("buf"):w(tmp):w("ene", 2):ws("haha"):wsl("haha"):wsl("haha", 4):w8(1):w16(2):w32(3):w64(4) )
	print( buf.buf ) 
	print( buf.len ) 
	print( buf.md5 ) 
	print( buf.sha1 ) 
	print( buf.crc ) 
	print( buf.b64 ) 
	print( buf.hex )
	print( buf:r(3) )
	print( buf:r(3, socklib.FMT.STR ) )
	print( buf:r(3, socklib.FMT.HEX ) )
	print( buf:r(3, socklib.FMT.B64 ) )
	print( buf:r(3, socklib.FMT.BIN ) )
	print( buf:r(3, socklib.FMT.BUF ) )

	buf = socklib.buf():w("12345")
	print( buf:sub():ps() )
	print( buf:sub(1):ps() )
	print( buf:sub(1, -1):ps() )
	print( buf:sub(1, -2):ps() )
	print( buf:sub(1, -2, socklib.FMT.STR) )
	print( buf:sub(1, -2, socklib.FMT.B64) )
	print( util.b64dec(buf:sub(1, -2, socklib.FMT.B64)) )

	local tcp = socklib.tcp();
	local sbf = tcp.outBuf;
	print( sbf:ws("tcp_data") )
	print( sbf:ps() )
	print( sbf:discard(2) )
	print( sbf:skip(2):ps() )
	print( sbf:rs() )
	print( sbf )
end

local function test_tcpserver()
end

-- socklib.tcp is a async socket
-- socklib.tcp().inbuf return it’s byte stream socklib.buf
-- socklib.tcp().outbuf return it‘s byte stream socklib.buf
-- ...

local function test_tcpclient()
	sk = socklib.tcp()

	sk:onevent(socklib.EVT.CONNECT, function(event)
		print("sk:onevent(" .. socklib.EVT.CONNECT .. ")")
		-- sk:send(...) == sk.outbuf:w(...)
		-- sk:setopt(socklib.OPT.RECVTIMEOUT, 2)
		sk:send("GET / HTTP/1.1\r\nHost:www.baidu.com\r\n\r\n")
	end)

	sk:onevent(socklib.EVT.CLOSE, function(event)
		print("sk:onevent(" .. socklib.EVT.CLOSE .. ")")

		local is = sk.inbuf
		print( is:rs() )

		-- TOFIX: will cause PANIC error
--		sk = nil

		collectgarbage("collect")
	end)

	sk:onevent(socklib.EVT.RECV, function(event)
		local is = sk.inbuf
		print("sk:onevent(" .. socklib.EVT.RECV .. ") total = " .. tostring(is.len))
	--	print(is:r(is.len))
	--	is:discard(is.len)
	--	is = nil
	end)

	sk:connect("www.baidu.com", 80)
end

local function test_udpserver()
end

local function test_udpclient()
end

local function print_table(prefix, tbl)
	print("@ " .. prefix)
	for k, v in pairs(tbl) do
		if not string.find(tostring(k), "__") then
			print(prefix .. "." .. tostring(k) .. "=" .. tostring(v))
		end
	end
end

local function test_socklib_info()
	print("@ " .. socklib._VERSION)

	print_table("socklib", socklib)
	print_table("socklib.tcp", getmetatable(socklib.tcp()))
	print_table("socklib.udp", getmetatable(socklib.udp()))
	print_table("socklib.buf", getmetatable(socklib.buf()))
	print_table("socklib.EVT", socklib.EVT)
	print_table("socklib.OPT", socklib.OPT)
	print_table("socklib.FMT", socklib.FMT)
	print_table("socklib.util", socklib.util)
	print_table("socklib.util.md5", getmetatable(socklib.util.md5()))
	print_table("socklib.util.sha1", getmetatable(socklib.util.sha1()))
	print_table("socklib.util.rc4", getmetatable(socklib.util.rc4()))
end

-- method/member name of obj which belongs to socklib is insensitive
--		obj.XXX  == obj.xxx  == obj.XxX  ...
--		obj:XX() == obj:xx() == obj:Xx() ...
local function test_socklib_nocase()
	print( socklib.TCP )
	print( socklib.uDp() )
	print( socklib.buf() )
	print( socklib.util.Rc4() )
	print( socklib.uTil.B64Enc("haha") )
	print( socklib.uTil.TiCK() )
	print( socklib.UtiL.MD5():Update("ssf"):Final() )
	print( socklib.utiL.md5():update("ssf"):final() )
	print( socklib.UtiL.SHA1():Update("ssf"):Final() )
	print( socklib.utiL.sha1():update("ssf"):final() )
	print( socklib.OPt.reUseaddr )
	print( socklib.evt.CONNECT )
end


--collectgarbage("collect")

test_socklib_info()
test_socklib_nocase()

test_util_ipprobe()

--test_util_timer()

--test_util_md5()
--test_util_sha1()
--test_util_rc4()
--test_util_crc32()
--test_util_base64()
--test_util_u32op()
--test_util_other()

test_buf()
--test_tcpserver()
--test_tcpclient()
--test_udpserver()
--test_udpclient()

