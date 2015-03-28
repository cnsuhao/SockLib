
function test_util_md5()
	print("---------------------test_util_md5() {")

	local util = socklib.util

	-- 1 a md5 function
	print( util.md5("hello") )

	-- 2 a md5 obj
	print( util.md5():init():update("hello"):final() )

	-- 3 more step update data and data
	print( util.md5():init():update("he"):update("llo"):final() )

	-- 4 socklib.buf is a byte stream
	local buf = socklib.buf():w("hello")
	print( util.md5(buf) )
	print( util.md5():init():update(buf):final() )

	-- 5 final(out_format: nil/hex=default, bin=lightuserdata, buf=socklib.buf)
	local bbb = util.md5():init():update("hello"):final("buf")
	print( bbb )

	print("---------------------test_util_md5() }")
end


function test_util_sha1()
	print("---------------------test_util_sha1() {")

	local util = socklib.util

	-- 1 a sha1 function
	print( util.sha1("hello") )

	-- 2 a sha1 obj
	print( util.sha1():init():update("hello"):final() )

	-- 3 more step update data and data
	print( util.sha1():init():update("he"):update("llo"):final() )

	-- 4 socklib.buf is a byte stream
	local buf = socklib.buf():w("hello")
	print( util.sha1(buf) )
	print( util.sha1():init():update(buf):final() )

	-- 5 final(out_format: nil/hex=default, bin=lightuserdata, buf=socklib.buf)
	local bbb = util.sha1():init():update("hello"):final("buf")
	print( bbb )

	print("---------------------test_util_sha1() }")
end

function test_util_rc4()
	print("---------------------test_util_rc4() {")

	local util = socklib.util

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

	print("---------------------test_util_rc4() }")
end

function test_util_crc32()
	print("---------------------test_util_crc32() {")

	local util = socklib.util

	-- util.crc32(a string or a lightudata or a socklib.buf, optinal len, optinal salk)

	print( util.crc32("haha") )
	print( util.crc32("haha", 4) )
	print( util.crc32("haha", 4, 0) )
	print( util.crc32("haha", 4, 123) )

	-- socklib.buf is a byte stream
	print( util.crc32( socklib.buf():w("haha") ) )

	print("---------------------test_util_crc32() }")
end

function test_util_base64()
	print("---------------------test_util_base64() {")

	local util = socklib.util

	local e = util.b64enc("haha")
	local d = util.b64dec(e)

	print(e)
	print(d)

	print("---------------------test_util_base64() }")
end

function test_util_u32op()
	print("---------------------test_util_u32op() {")

	local util = socklib.util

	-- 2 args = socklib.util.u32op("opt_str", num)
	print( util.u32op("!", 123) )
	print( util.u32op("~", 123) )

	-- 3 args = socklib.util.u32op(num1, "opt_str", num2)
	print( util.u32op(123, "<<", 2) )
	print( util.u32op(123, "&", 2) )
	print( util.u32op(123, "|= ~", 2) )

	print("---------------------test_util_u32op() }")
end

function test_util_other()
	print("---------------------test_util_other() {")

	local util = socklib.util

	print( util.tick() )
	print( util.urlenc("http://aa.bb.cc/dd ee.asp") )
	print( util.urldec(util.urlenc("http://aa.bb.cc/dd ee.asp")) )
	print( util.ips2n("192.168.0.1") )
	print( util.ipn2s(util.ips2n("192.168.0.1")) )

	print("---------------------test_util_other() }")
end

-- socklib.buf is a byte stream
-- write:  w() wl() ws() wsl() w8() w16() ....
-- read:   r() rl() rs() rsl() r8() r16() ....
-- peek:   p() pl() ps() psl() p8() p16() ....
-- skip/discard:   skip() == discard()
-- ...
function test_buf()
	print("---------------------test_buf() {")

	local tmp = socklib.buf():ws("tmp")
	local buf = socklib.buf();
	print( buf:w("buf"):w(tmp):w("ene", 2):ws("haha"):wsl("haha"):wsl("haha", 4):w8(1):w16(2):w32(3):w64(4) )

	local tcp = socklib.tcp();
	local sbf = tcp:sendBuf();
	print( sbf:ws("tcp_data") )
	print( sbf:ps() )
	print( sbf:discard(2) )
	print( sbf:skip(2):ps() )
	print( sbf:rs() )
	print( sbf )

	print("---------------------test_buf() }")
end

function test_tcpserver()
end

-- socklib.tcp is a async socket
-- socklib.tcp().inbuf return it’s byte stream socklib.buf
-- socklib.tcp().outbuf return it‘s byte stream socklib.buf
-- ...
function test_tcpclient()
	print("---------------------test_http() {")

	sk = socklib.tcp()

	sk:onevent(socklib.EVT.CONNECT, function(event)
		print("sk:onevent(connect)")
		-- sk:send(...) == sk.outbuf:w(...)
		sk:setopt(socklib.OPT.RECVTIMEOUT, 2)
		sk:send("GET / HTTP/1.1\r\nHost:www.baidu.com\r\n\r\n")
	end)

	sk:onevent(socklib.EVT.CLOSE, function(event)
		print("sk:onevent(close)")

		local is = sk.inbuf
		print( is:rs() )

		-- TODOFIX: will cause PANIC error
--		sk = nil

		collectgarbage("collect")
	end)

	sk:onevent(socklib.EVT.RECV, function(event)
		local is = sk.inbuf
		print("sk:onevent(recv) total = " .. tostring(is.length))
	--	print(is:r(is.length))
	--	is:discard(is.length)
		is = nil
	end)

	sk:connect("www.baidu.com", 80)

	print("---------------------test_http() }")
end

function test_mjclient()
	local EVT = socklib.EVT
	local U32OP = socklib.util.u32op

	sk = socklib.tcp()

	sk:onevent(EVT.CONNECT, function(evt)

		local ver = U32OP(U32OP(U32OP(1, "<<", 16), "|", U32OP(1, "<<", 8)), "|", 1)
		local flg = 2

		sk.outbuf:w("GmCltMJ\0", 8):w32(ver):w32(flg):w("12345678901234567890", 16):w(string.rep("\0", 32))
	end)

	sk:onevent(EVT.CLOSE, function(evt)
	end)

	sk:connect("127.0.0.1", 6000)
end

function test_udpserver()
end

function test_udpclient()
end

function print_table(prefix, tbl)
	print("@ " .. prefix)
	for k, v in pairs(tbl) do
		if not string.find(tostring(k), "__") then
			print(prefix .. "." .. tostring(k) .. "=" .. tostring(v))
		end
	end
end

function test_socklib_info()
	print("---------------------test_socklib_info() {")

	print("@ " .. socklib._VERSION)

	print_table("socklib", socklib)
	print_table("socklib.tcp", getmetatable(socklib.tcp()))
	print_table("socklib.udp", getmetatable(socklib.udp()))
	print_table("socklib.buf", getmetatable(socklib.buf()))
	print_table("socklib.EVT", socklib.EVT)
	print_table("socklib.OPT", socklib.OPT)
	print_table("socklib.util", socklib.util)
	print_table("socklib.util.md5", getmetatable(socklib.util.md5()))
	print_table("socklib.util.sha1", getmetatable(socklib.util.sha1()))
	print_table("socklib.util.rc4", getmetatable(socklib.util.rc4()))

	print("---------------------test_socklib_info() }")
end

-- method/member name of obj which belongs to socklib is insensitive
--		obj.XXX  == obj.xxx  == obj.XxX  ...
--		obj:XX() == obj:xx() == obj:Xx() ...
function test_socklib_nocase()
	print("---------------------test_socklib_nocase() {")

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

	print("---------------------test_socklib_nocase() }")
end

test_socklib_info()
test_socklib_nocase()

--print( socklib.buf():w("123\12\44\AB").sha1 )

--test_util_md5()
--test_util_sha1()
--test_util_rc4()
--test_util_crc32()
--test_util_base64()
--test_util_u32op()
--test_util_other()

--test_buf()
--test_tcpserver()
--test_tcpclient()
--test_udpserver()
--test_udpclient()

