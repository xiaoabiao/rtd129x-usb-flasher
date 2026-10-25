RTD129x（RTD1295 / RTD1296）USB 线刷工具 —— 安装与使用说明
================================================================

一、这是什么
------------
Realtek RTD129x USB 线刷工具（rtumdfsample.exe）的 64 位重写版，
用于把 install.img 烧写到板子的 eMMC。相比原版：

  * 64 位：可以刷大于 2 GB、甚至单个成员大于 4 GB 的完整包
    （实测 7.82 GB 单包、7.0 GB 单个 p2.img，刷完正常启动 fnOS）
  * 完整还原：hwsetting → DDR enable → 低区 → boot → rootfs → MBR → factory
  * 大分区流式读取，不会把整个镜像读进内存

二、依赖环境
------------
1) 运行库：不需要。只用 Windows 自带系统 DLL（Win7 及以上即可），
   不需要 .NET、VC++ 运行库、Python。
2) 数据文件：hwsetting 文件夹必须和 exe 同目录（安装包已自带）。
   本板（CM360 / RTD1296）DDR 类型选 “4DDR4_2GB”。
3) USB 驱动：板子需要原厂 Realtek UMDF 驱动（设备管理器显示
   “Realtek generic USB Device”，VID_0BDA&PID_1195）。
   - 已经能看到这个设备 → 什么都不用装；
   - 看不到 → 先让板子进入下载模式并插好 USB，再运行开始菜单
     「RTD-Flasher → 安装 USB 驱动（管理员）」（会弹 UAC）。
   - 不要用 Zadig 换成 WinUSB，否则工具读不到板子。

三、烧写步骤
------------
1. 板子断电，进入 USB 下载模式。
2. 打开「RTD129x 线刷工具」。
3. 选择 install.img；DDR 类型选 4DDR4_2GB。
4. 点「加载」，确认「分区 / 写入项」列表正确
   （应含低区 3000000、PART0/PART1…、MBR0、FACTORY_A/B）。
5. 「扫描设备」→「开始烧写」。
6. 等完成（2.4 GB 约 7 分钟，7.8 GB 约 24 分钟），给板子断电重启。

四、命令行（可选）
------------------
  rtd-flash.exe devices                         列出设备
  rtd-flash.exe plan  <install.img> 4DDR4_2GB   干跑：打印帧序列，不碰设备
  rtd-flash.exe burn  <install.img> 4DDR4_2GB   实刷

五、目录说明
------------
  rtd-gui.exe            图形界面（主程序）
  rtd-flash.exe          命令行
  hwsetting\             DDR 配置表（必须与 exe 同目录）
  driver\                原厂 USB 驱动包（仅新电脑需要时用）
  docs\                  逆向交接文档与协议说明
  install-driver.ps1     安装 USB 驱动（会弹 UAC）
  uninstall.ps1          卸载

六、常见问题
------------
Q: 「找不到 hwsetting 文件」？
A: 确认 hwsetting 文件夹和 rtd-gui.exe 在同一目录，且含三个 .bin。

Q: 「扫描设备」找不到板子？
A: 1) 确认板子真的进了 USB 下载模式；
   2) 设备管理器看有没有 “Realtek generic USB Device”；
   3) 没有就先装驱动；
   4) 换主板直出的 USB 口，别走外接 Hub。

Q: 烧写中途失败/超时？
A: 给板子断电重来。烧写前必须冷启动进入下载模式；
   上一次中断留下的状态会让设备拒绝新的 hwsetting。

Q: 支持 NAND / NOR / eFuse / 安全密钥吗？
A: 不支持，与原厂工具范围一致（缺 GenKeyBag.exe，NAND 需要坏块重映射）。

七、卸载
--------
开始菜单 → RTD-Flasher → 「卸载 RTD-Flasher」，或直接删除
%LOCALAPPDATA%\Programs\RTD-Flasher 目录及快捷方式。
卸载不会动你的镜像、日志或板子。

（开源项目：https://github.com/xiaoabiao/rtd129x-usb-flasher ）
