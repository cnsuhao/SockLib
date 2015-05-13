# SockLib

一个在 Lua 5.1 中使用的网络库，异步非阻塞模式，含 TCP/UDP、Buffer(字节流)，另包含 MD5、SHA1、RC4、CRC32、Base64、u32op(位操作)算法，全部都做在两个文件 SockLib.cpp/.h 里

在 Cocos2d-x Lua 3.5 中使用范例：

    1、将 SockLib.cpp/.h 两个文件 Copy 进项目 Classes 下
  
    2、修改 Classes/lua_module_register.h 文件，添加 #include "SockLib.h" 和 socklib::SockLib::luaRegLib(L);
  
    3、本库是以 SockLib::poll(usec) 来驱动运作的，可以在每一帧 update() 事件里调用此函数。举例一个修改方式是
  
      a)、给 AppDelegate.h 添加一个成员函数 void update(float dt);
    
      b)、给 AppDelegate.cpp 添加
    
          void AppDelegate::update(float dt)
          {
          	  socklib::SockLib::poll(0);
          }
        
      c)、在 AppDelegate.cpp 的 AppDelegate::applicationDidFinishLaunching() 函数末尾添加
    
        	cocos2d::Director::getInstance()->getScheduler()->scheduleUpdate<AppDelegate>(this, 0, false);

    4、即可

特点：

    本库的使用默认是“大小写无关”的（除了 socklib 这个库名），比如 socklib.Util 和 socklib.util、socklib.uTiL 是等效的，由 SockLib.h 里的宏 SOCKLIB_NOCASE 控制
    
范例：

    请参考 socklib_test.lua
