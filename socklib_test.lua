
function test_md5()
	print("---------------------test_md5() {")

	-- 1 a md5 function
	print( socklib.md5("hello") )

	-- 2 a md5 obj
	print( socklib.md5():init():update("hello"):final() )

	-- 3 more step update data and data
	print( socklib.md5():init():update("he"):update("llo"):final() )

	-- 4 socklib.buf is a byte stream
	local buf = socklib.buf():w("hello")
	print( socklib.md5(buf) )
	print( socklib.md5():init():update(buf):final() )

	-- 5 final(out_format: nil/hex=default, bin=lightuserdata, buf=socklib.buf)
	local bbb = socklib.md5():init():update("hello"):final("buf")
	print( bbb )

	print("---------------------test_md5() }")
end


function test_sha1()
	print("---------------------test_sha1() {")

	-- 1 a sha1 function
	print( socklib.sha1("hello") )

	-- 2 a sha1 obj
	print( socklib.sha1():init():update("hello"):final() )

	-- 3 more step update data and data
	print( socklib.sha1():init():update("he"):update("llo"):final() )

	-- 4 socklib.buf is a byte stream
	local buf = socklib.buf():w("hello")
	print( socklib.sha1(buf) )
	print( socklib.sha1():init():update(buf):final() )

	-- 5 final(out_format: nil/hex=default, bin=lightuserdata, buf=socklib.buf)
	local bbb = socklib.sha1():init():update("hello"):final("buf")
	print( bbb )

	print("---------------------test_sha1() }")
end

function test_rc4()
	-- 1 a rc4 function
	print( socklib.rc4("key_aa", "data_bb") )

	-- 2 a rc4 obj
	print( socklib.rc4():setKey("key_aa"):process("data_bb") )

	-- 3 use fun: rc4(rc4_data) = originally data
	local buf = socklib.rc4("key_aa", "data_bb")
	print (socklib.rc4("key_aa", buf):ps() )

	-- 4 use obj: rc4(rc4_data) = originally data
	local buf = socklib.rc4():setKey("key_aa"):process("data_bb")
	print (socklib.rc4():setKey("key_aa"):process(buf):ps() )
end

function test_crc32()
	-- socklib.crc32(a string or a lightudata or a socklib.buf, optinal len, optinal salk)

	print( socklib.crc32("haha") )
	print( socklib.crc32("haha", 4) )
	print( socklib.crc32("haha", 4, 0) )
	print( socklib.crc32("haha", 4, 123) )

	-- socklib.buf is a byte stream
	print( socklib.crc32( socklib.buf():w("haha") ) )
end

function test_base64()
--	local e = socklib.b64enc("haha")
--	local d = socklib.b64dec(e)

--	print(e)
--	print(d)
end

function test_u32op()
	print("---------------------test_u32op() {")

	-- 2 args = socklib.u32op("opt_str", num)
	print( socklib.u32op("!", 123) )
	print( socklib.u32op("~", 123) )

	-- 3 args = socklib.u32op(num1, "opt_str", num2)
	print( socklib.u32op(123, "<<", 2) )
	print( socklib.u32op(123, "&", 2) )
	print( socklib.u32op(123, "|= ~", 2) )

	print("---------------------test_u32op() }")
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
-- socklib.tcp():recvBuf() return it’s byte stream socklib.buf
-- socklib.tcp():sendBuf() return it‘s byte stream socklib.buf
-- ...
function test_tcpclient()
	print("---------------------test_http() {")

	sk = socklib.tcp()

	sk:onEvent("connect", function(event)
		print("sk:onEvent(connect)")
		-- sk:send(...) == sk:sendBuf():w(...)
		sk:send("GET / HTTP/1.1\r\nHost:www.baidu.com\r\n\r\n")
	end)

	sk:onEvent("close", function(event)
		print("sk:onEvent(close)")

		local rbuf = sk:recvBuf()
		print( rbuf:rs() )

		-- TODOFIX: will cause PANIC error
--		sk = nil

		collectgarbage("collect")
	end)

	sk:onEvent("recv", function(event)
		local rbuf = sk:recvBuf()
		print("sk:onEvent(recv) total = " .. tostring(rbuf:length()))
	--	print(rbuf:r(rbuf:length()))
	--	rbuf:discard(rbuf:length())
		rbuf = nil
	end)

	sk:connect("www.baidu.com", 80)

	print("---------------------test_http() }")
end

function test_udpserver()
end

function test_udpclient()
end

--test_md5()
--test_sha1()
--test_rc4()
--test_crc32()
--test_base64()
--test_u32op()
--test_buf()
--test_tcpserver()
test_tcpclient()
--test_udpserver()
--test_udpclient()


