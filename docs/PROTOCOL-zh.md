# Realtek RTD1295 / RTD1195 USB "线刷" 工具 —— 逆向与重写指南

被分析目标：`w2_android_usb_download_tool\rtumdfsample.exe`
（PE32 i386 GUI，MSVC 11.0 / VS2012，静态链接 MFC）
SHA-256：`c29ba32b5ce1e5d0393bab777fe39d8405161e871dd0c2cf1766ee74f18a0bd0`

工具包里 `rtumdfsample.pdb` 是**同一次构建的完整调试符号**（GUID `18e2c3bf-fc28-d145-ac12-305158217c32`，age 15），
因此本次逆向拿到了接近源码级的精度：14145 个函数、9198 个函数↔源码行映射、全部结构体/枚举布局。

---

## 1. 这套工具到底在做什么

板上 SoC 处于 **Device 模式**时，通过 USB 暴露一个厂商接口（不是标准 U 盘）：

| 项目 | 值 |
|---|---|
| VID / PID | `0bda` / `1195` |
| 设备接口 GUID | `{7B56A5D6-CD10-4410-9F59-9A5E71269882}` |
| 驱动 | `rtumdfdrv`（UMDF/`rtumdfsample` 用户态驱动，INF 里 `USB\Vid_0bda&Pid_1195`） |
| 访问方式 | `CreateFileA` 拿到句柄后 **纯 `WriteFile` / `ReadFile`**（USBD 批量管道），无 `DeviceIoControl` |
| 最大单次请求 | `0x20000`（128 KiB，驱动侧限制） |

工具通过一个 **仿 SCSI 的 CBW/CSW 帧**下发自定义命令，把
bootloader（u-boot/LK、FSBL、TEE、BL31、hw_setting）和 Android/OpenWrt 系统镜像
（`install.img`，内部是 `FW_*` / `W_FW_*` 成员）写进 eMMC / NAND / NOR，
最后写 factory 区、efuse、secure key。

---

## 2. 传输层协议（重写时最关键的部分）

### 2.1 CBW 帧（主机 → 设备，43 字节）

```
偏移  长度  字段
0x00   4    dCBWSignature       0x43425355  ('USBC' 小端)
0x04   4    dCBWTag             0x12345678
0x08   4    dCBWDataTransferLength   本次数据长度（0x2B 帧里为 5）
0x0C   1    bmCBWFlags          0x80=读方向, 0x00=写方向
0x0D   1    iIndicator          分片指示: 1=首片, 0=中间片, 3=末片
                                高 4 位是模式位 ((p16&3)|(p17<<2))<<4
0x0E   1    bCBWCBLength        28 (0x1C)
0x0F  28    CBWCB[]             见下
----------------------------------------------------
合计 43 字节（源码里 push 0x2b = 43）
```

> 注意：这不是标准 SCSI。CBWCB 长度 28 而不是 16，CSW 长度 50 而不是 13。

### 2.2 CBWCB[28]（`_CBWCB`，PDB 直接给出）

```
+0x00  u8   OPCode                 顶层命令 0xF1..0xFC
+0x01  u8   Type                   子命令/标志（0x06 = DDR enable, 0x01 = 写数据块）
+0x02  u32  LogicalBlockAddress    bootloader 路径=512B 扇区号；usb_hwsetting=裸字节地址 0x1500000
+0x06  u8   NandEccBit
+0x07  u8   flashType              0=NAND, 1=NOR, 2=EMMC
+0x08  u16  PageSize
+0x0A  u32  blockSize
+0x0E  u32  nandSize
+0x12  u16  Spare                  spare/OOB 值；==0x79 且启用重映射时高字节带 remap 索引
+0x14  u32  WriteSpecialSize
+0x18  u32  CRC32                 本片 payload 的 CRC32
```

### 2.3 CSW 帧（设备 → 主机，50 字节）

```
+0x00  u32  dCSWSignature   0x53425355 ('USBS')
+0x04  u32  dCSWTag         0x12345678
+0x08  ...  residue / sense 区
+0x0D  u8   bCSWStatus      见下表
合计 50 字节（源码 cmp esi,0x14 后读 0x32）
```

`bCSWStatus` 在 **偏移 13**（不是 SCSI 的 12）。反汇编证据：`0x405f7a` 处
`mov byte ptr [ebp-0x8f], 2`，而 CSW 缓冲区基址是 `ebp-0x9c`，`0x9c-0x8f = 13`；
随后 `0x406053` 用 `[ebp-0x8f]` 做 7 路跳转表（表在 `0x406dc8`）。

| 值 | 枚举 | 含义 |
|---|---|---|
| 0 | `CSW_STAT_PASS` | 成功 |
| 1 | `CSW_STAT_FAIL` | 失败，重试 |
| 2 | `CSW_STAT_BUSY` | 设备忙，继续轮询 |
| 3 | `CSW_STAT_WFAIL` | NAND 写坏块，触发重映射 |
| 4 | `CSW_STAT_WKEYFAIL` | 写 key 失败 |
| 5 | `CSW_STAT_WKEYPASS` | 写 key 成功 |
| 6 | `CSW_STAT_RKEYFAIL` | 读 key 失败 |

### 2.4 一次写入的完整时序

```
1) 轮询/清状态（仅 TestReadDevice 路径）
   Write CBW{sig,tag,len=5,flags=0,iInd=0,op=0x1C}   (43B)
   Write 5 字节通道帧
   Read  CSW (50B) → status==2 表示 BUSY，Sleep(200ms) 再轮询

2) 对每个分片：
   Write CBW{sig,tag,len=payload,flags,iIndicator,op,len=28,CBWCB[28]}   (43B)
   Write payload
   Read  CSW (50B)
   校验 [0..3]=='USBS'、[4..7]==0x12345678，取 [13] 作为状态

3) 重试策略：最多 200 次，每次间隔 200 ms，整体超时 20 s
```

### 2.5 命令字（OPCode）与实现位置

| OPCode | 名称 | 处理函数（源码文件:行） |
|---|---|---|
| `0xF1` | SE_STORAGE（安全存储 key） | `se_storage_burner` @ key_write.cpp:89 |
| `0xF2` | SINGLE_WRITE 状态 | `single_burner` @ single_write.cpp:32 |
| `0xF3` | NAND 写（含 BBT 重映射） | `nand_burner` @ nand_write.cpp:32 |
| `0xF4` | **eMMC/通用批量写（主力，66 处调用）** | `WriteDevice` @ dev_api.cpp:104 |
| `0xF5` | USB hwsetting / DRAM 初始化 | `usb_hw_setting_burner` @ rtumdfsampledlg.cpp:4643 |
| `0xF6` | 写验证测试 | `TestWriteDevice` @ dev_api.cpp:828 |
| `0xF9` | efuse 烧写 | `efuse_burner` @ key_write.cpp:686 |
| `0xFA` | DDR enable（type=0x06，**载荷 5 字节 `"test\0"`**；hwsetting 写完先 `Sleep(1500ms)` 再发，设备必回 CSW） | `usb_hw_setting_burner` |
| `0xFB` | SINGLE_WRITE 数据 | `single_burner` @ single_write.cpp:32 |
| `0xFC` | 读验证测试 | `TestWriteDevice` / `TestReadDevice` |
| `0x1C` | 状态/通道轮询（CBWCBLength=0x1C） | `TestReadDevice` @ dev_api.cpp:1079 |

---

## 3. 烧写流程（`ThreadProgramDevice` @ rtumdfsampledlg.cpp:1541）

```
OpenDevice()
  ↓
ReadFlashInfo()              从 GUI 控件读出 _FlashInfo 全部字段
  （flashType/nandSize/blockSize/pageSize/eccBit/start_addr/trans_size/
    write_special_count/cover_value/spare_value/once_trans_max_size/
    secure_option/go_or_jump_opetion/read_data_range/read_spare_count）
  ↓
usb_hw_setting_burner()
  ├─ prepareUsbHWBuf()       拼 DDR/hwsetting 数据块（AES 保护）
  ├─ WRITE 0xF5  LBA=0x1500000  + 读 CSW（约 28ms）
  ├─ Sleep(1500ms)           ← 必须：等板子应用 DRAM 配置（抓包实测间隔 1512ms）
  └─ WRITE 0xFA  type=0x06 + 载荷 "test\0" → 读 CSW（DDR enable，不是空操作！）
  ↓
check_burn_options()         feature 分派（见 SYSTEM.ini 开关）
  ↓
bootloader.tar 成员逐个写：
  hw_setting.bin → LBA 256
  uboot.bin      → LBA 263   (= 256 + ceil(3200/512))
  fsbl.bin       → LBA 1443  (= 263 + ceil(604128/512))
  tee.bin        → LBA 1585  (= 1443 + ceil(72544/512))
  （日志实测："uboot hwsetting address ... start block : 256"、
     "boocode address ... start block 263"、"uboot FSBL address ... 1443"）
  ↓
emmc_burner / nand_burner / single_burner
  按 layout.txt 逐分区写 install.img 成员（FW_KERNEL / FW_KERNEL_ROOTFS / ...）
  NAND 路径带坏块表（_BB_t / _BBT_List）与 remap 逻辑
  ↓
key_burner()                 key bag / SN / MAC / se_storage
  ↓
factory_burner()             factory.tar 写到 factory 区
  （实测 start page 4352 / 8448 → 字节偏移 0x220000 / 0x420000，上限 0x200000）
  ↓
efuse_burner()               0xF9 烧 efuse（efuse_programmer.complete.enc）
  ↓
可选 compare 校验 → CloseDevice()
```

**LBA 换算规则已用日志验证**：`next = cur + ceil(size/512)`，即 512 字节扇区号。

---

## 4. 数据结构

```c
typedef struct _FlashInfo {          // size 64
    /*+0x00*/ unsigned char  flashType;          // 0=NAND 1=NOR 2=EMMC
    /*+0x04*/ unsigned int   nandSize;           // MB
    /*+0x08*/ unsigned int   blockSize;          // KB
    /*+0x0C*/ unsigned int   pageSize;
    /*+0x10*/ unsigned char  eccBit;
    /*+0x14*/ unsigned int   start_addr;
    /*+0x18*/ long long      trans_size;
    /*+0x1C*/ unsigned int   write_special_count;
    /*+0x20*/ long long      cover_value;
    /*+0x28*/ unsigned short spare_value;
    /*+0x2C*/ unsigned int   once_trans_max_size;
    /*+0x30*/ int            secure_option;
    /*+0x34*/ int            go_or_jump_opetion;
    /*+0x38*/ unsigned int   read_data_range;
    /*+0x3C*/ unsigned int   read_spare_count;
} FlashInfo;

typedef struct type_deviceInfo {     // size 848
    void        *hDevice;                    // +0x000
    long long    nor_flash_binary_len;       // +0x008
    long long    hwsettingRemainLen;         // +0x010
    long long    UserDataRemainLen;          // +0x018
    long long    SpecialRemainLen;           // +0x020
    long long    GoaddrRemainLen;            // +0x028
    long long    GoaddrPtLen[3];             // +0x030
    long long    usb_hwLen;                  // +0x048
    long long    hwLen;                      // +0x050
    long long    LK_Len;                     // +0x058
    long long    fsbLen;                     // +0x060
    long long    tee_enc_Len;                // +0x068
    long long    bl31_enc_Len;               // +0x070
    long long    rsa_bin_fw_Len;             // +0x078
    long long    rsa_bin_tee_Len;            // +0x080
    long long    FW_Kernel_Len;              // +0x088
    /* ... FW_*_Len 每个成员一个 long long，直到 ... */
    long long    FW_Gold_Akernel_Len;        // +0x140
    long long   *FW_Part_Len;                // +0x148
    long long    FW_MBR_Len[30];             // +0x150
    int          Start;                      // +0x240
    int          bResult;                    // +0x244
    char         strDevPath[260];            // +0x248
} type_deviceInfo;

typedef struct _BB_t {               // size 8
    unsigned short BB_die, bad_block, RB_die, remap_block;
} BB_t;

typedef struct _BBT_List {           // size 12
    BB_t *BBT; long rmp_blk_used_count, rmp_blk_max_count;
} BBT_List;

typedef struct st_LoadLayoutData {   // size 40
    const char *target;  long long length;  unsigned char *buffer;
    long long addrOffset;  unsigned int memAddress;
} st_LoadLayoutData;
```

### 4.1 `Layout_Type[24]` ↔ `type_deviceInfo.FW_*_Len` 的完整对应（已坐实）

`Layout_Type` 是 `.data` 里的一个 **24 项 × 0x28 字节**的全局数组（`st_LoadLayoutData` 数组），
成员名由 `??__ELayout_Type@@YAXXZ` 动态初始化器在启动时用 CString 逐个构造。
`set_device_info_value()`（0x00426bd0，writefactory.cpp）把 `Layout_Type[n].length`
直接抄进 `type_deviceInfo` 的对应字段 —— 反编译代码里字段名和下标是一一对应的：

| idx | 元素偏移 | 成员名（install.img 里的 tar 成员） | type_deviceInfo 字段 |
|----|---------|-----------------------------------|----------------------|
| 0  | 0x000 | `FW_KERNEL `              | `FW_Kernel_Len` |
| 1  | 0x028 | `FW_RESCUE_DT `           | `FW_Rescue_DT_Len` |
| 2  | 0x050 | `FW_KERNEL_DT `           | `FW_Kernel_DT_Len` |
| 3  | 0x078 | `FW_RESCUE_ROOTFS `       | `FW_Rescue_RootFS_Len` |
| 4  | 0x0A0 | `FW_KERNEL_ROOTFS `       | `FW_Kernel_RootFS_Len` |
| 5  | 0x0C8 | `FW_NAS_RESCUE_KERNEL `   | `FW_Nas_Rescue_Kernel_Len` |
| 6  | 0x0F0 | `FW_NAS_RESCUE_DT `       | `FW_Nas_Rescue_DT_Len` |
| 7  | 0x118 | `FW_NAS_RESCUE_ROOTFS `   | `FW_Nas_Rescue_RootFS_Len` |
| 8  | 0x140 | `FW_AKERNEL `             | `FW_Akernel_Len` |
| 9  | 0x168 | `FW_TEEKERNEL `           | `FW_Teekernel_Len` |
| 10 | 0x190 | `FW_BL31 `                | `FW_Bl31_Len` |
| 11 | 0x1B8 | `FW_P_UBOOT `             | `FW_Puboot_Len` |
| 12 | 0x1E0 | `FW_DALOGO `              | `FW_Dalogo_Len` |
| 13 | 0x208 | `FW_DILOGO `              | `FW_Dilogo_Len` |
| 14 | 0x230 | `FW_CILOGO1 `             | `FW_Cilogo1_Len` |
| 15 | 0x258 | `FW_FWTBL `               | `FW_Table_Len` |
| 16 | 0x280 | `FW_CONFIG `              | `FW_Config_Len` |
| 17 | 0x2A8 | `FW_PROFILE `             | `FW_Profile_Len` |
| 18 | 0x2D0 | `FW_GOLD_KERNEL `         | `FW_Gold_Kernel_Len` |
| 19 | 0x2F8 | `FW_GOLD_RESCUE_DT `      | `FW_Gold_Rescue_DT_Len` |
| 20 | 0x320 | `FW_GOLD_ROOTFS `         | `FW_Gold_RootFS_Len` |
| 21 | 0x348 | `FW_GOLD_AKERNEL `        | `FW_Gold_Akernel_Len` |
| 22 | 0x370 | `FW_EFUSE_VERIFY `        | `FW_Efuse_Verify_Len` |
| 23 | 0x398 | `FW_EFUSE_PROGRAMMER `    | `FW_Efuse_Programmer_Len` |

> 注意成员名**末尾带一个空格**，`LoadFlashLayout` 用整串子串匹配时这个空格是有意义的。
> `FW_PROFILE ` 在 `ReadUnTarTempFile` 里有特殊处理：当分区数 ≥2 时它被跳过（不写数据）。

**动态分区**（`FW_Part_Len`）：`TotalPartitonCutNum` 个 `long long`，从 `m_PartStructPt`
数组按 0x28 步长逐个取 `length`（`set_device_info_value` 里可见）。
**MBR**：`FW_MBR_Len[30]`，从 `m_MbrStructPt` 同样按 0x28 步长填 `MbrNumber` 个。

证据链：
- `set_device_info_value` 反编译代码里 `Layout_Type[0].length` → `FW_Kernel_Len`、
  `Layout_Type[0x17].length` → `FW_Efuse_Programmer_Len` 的逐行赋值。
- `efuse_burner` 里直接用 `param_3[0x17].target == "FW_EFUSE_PROGRAMMER "` 和
  `param_3[0x16].target == "FW_EFUSE_VERIFY "` 做字符串比对 —— 下标 0x17/0x16 与上表一致。
- `emmc_burner` 用 `Layout_Type[0].buffer/length` 配 `&param_2->FW_Kernel_Len` 调 `WriteDevice(0xF4)`。

`type_deviceInfo` 里 `FW_Kernel_Len` 到 `FW_Gold_Akernel_Len` 共 33 个 `long long`，
完整逐字段偏移已导出到 `index/types_full.txt`。

---

## 5. 加密

### 5.1 固件侧的两个独立用途（别混淆）

| 用途 | 算法/模式 | 密钥 | 位置 |
|---|---|---|---|
| **hwsetting / DRAM 初始化表** | AES-128-**ECB** | 硬编码常量 | `Tempfile\*.bin` |
| **enckey.bin（安全 key）** | AES-128-**CBC**，零 IV | **调用方传入**（来自 GenKeyBag.exe） | factory / se_storage 区 |

下面只讨论第一种，它跟刷固件有关。

### 5.2 hwsetting 是 AES-128-ECB，密钥硬编码

硬编码密钥（`.data`，符号 `?g_AES_USB_key@@3PAEA`）：

```
key = abcdef1213572468a1b2c3d49090babe   (16 字节)
```

> ⚠️ **修正**：早先版本本文档写的是"CBC + 零 IV"，那是**错的**。
> 误判原因：CBC 在 IV=0 时 `P1 = D(C1) XOR 0 = D(C1)`，**第一块恰好等于 ECB 的结果**。
> 当时看到前两对寄存器（`0x1801a010=0x1f`、`0x1801a004=0x31`）就下了结论，
> 后面全被当成"数据区"。实际用统计检验一测就清楚了——
> 统计 32 位字落在已知寄存器窗口（`0x1800xxxx` / `0x9800xxxx`）的比例：

| 文件 | ECB | CBC(零 IV) |
|---|---|---|
| `usb_hwsetting.bin` | **128/296** | 2/296 |
| `kylin_...2DDR3...` | **156/408** | 1/408 |
| `kylin_...2DDR4...` | **179/472** | 1/472 |

随机数据约 0%。ECB 高出两个数量级，是唯一正确解。解密后 `usb_hwsetting.bin`
的 **128 个** 寄存器地址全部落在 `0x18000000–0x1801A938`，正是 RTD129x 的 DDR 控制器区间。

### 5.3 解密结果：完整的 DDR 初始化寄存器表

`usb_hwsetting.bin`（1184 字节 = 148 对 `addr=value`，小端）解出来是这样：

```
0x1801A010 = 0x0000001F
0x1801A004 = 0x00000031
0x18000018 = 0x00000005
0x18000100 = 0x4D200043
0x18000104 = 0x03942801
0x18000110 = 0x00000005
0x18000158 = 0x0F7FF001
0x18000164 = 0x02761B52
0x1800705C = 0x00000003
0x18008004 = 0x094B0020
0x18008800 = 0x00179713
0x18008804 = 0x0307071B
...
0x18007078 = 0x80000001
```

末尾几对（偏移 `0x460` 之后）是校验/签名尾，地址字段不再是寄存器。

**kylin 那两个文件指向的是别的 SoC**：解密后高位字节直方图以 `0x98` 为主
（DDR4: `0x98xxxxxx` 188 个 / `0x00xxxxxx` 162 个），而 RTD1295 是 `0x18xxxxxx`。
同样的 AES 密钥，不同的寄存器地址空间 —— 说明那两个是给另一颗芯片（或另一版 DDR PHY）用的，
**跟你这块板子无关**，可以直接忽略。

解密 + 生成示例：

```python
from Crypto.Cipher import AES
key = bytes.fromhex("abcdef1213572468a1b2c3d49090babe")
plain = AES.new(key, AES.MODE_ECB).decrypt(open("usb_hwsetting.bin", "rb").read())

import struct
for i in range(0, len(plain) - 7, 8):
    addr, val = struct.unpack_from("<II", plain, i)
    print(f"{addr:#010x} = {val:#010x}")
```

- 重写工具时如果要生成自己的 hwsetting 数据，必须复用同一密钥，否则设备拒绝。
- 「三个文件前 16 字节相同」是因为它们的**前 5 个密文块**确实相同
  （CBC/ECB 下相同密文块 ⇔ 相同明文块），即 DDR3/DDR4 两种配置共享同一段初始化前缀。

### 5.4 与串口恢复工具的关系

`Desktop\key\boot_recovery.exe`（RTD1295/1296 的 UART 恢复工具，MFC/VC6 编译）
**完全不含加密**：无 AES/RSA/MD5/SHA 符号，导入表里也没有 `crypt32`。
它有 `hwconfig_to_Hwbinfile()` / `parse_line()` / `atoh()` / `swap()` / `MakeBlock0()`，
负责把文本 `.config` 转成 `HwConfig.bin` 再用 YMODEM 从串口上传。

也就是说：**`.config`（文本）→ `HwConfig.bin`（明文二进制）→ 加密后得到 `usb_hwsetting.bin`**。
USB 工具走的是 USB 通道 + AES，串口工具走的是 UART + YMODEM，两条独立路径。

---

## 5.5 `HwConfig.bin` 的格式（已从 exe 里完整逆出）

这是本次逆向最有价值的成果之一：**`hwsetting` 的明文格式已经完全还原**，
不用再猜，也**不需要 `.config` 样本**了。

### 逆向路径

`boot_recovery.exe` 里 `hwconfig_to_Hwbinfile` 的实际代码分布在两处：

| 函数 | 地址 | 作用 |
|---|---|---|
| 包装层（Ghidra 未命名） | `0x00401C30` | 取路径、DeleteFile、读对话框、调用转换 |
| **真正的转换器** | **`0x00404810`** | 打开 `.config` 逐行解析，写出二进制 |

辅助函数：

| 函数 | 地址 | 作用 |
|---|---|---|
| `FUN_00404DD0` | `0x00404DD0` | 写一个 **u32，逐字节 LSB→MSB**（小端） |
| `FUN_00404D60` | `0x00404D60` | 十六进制解析（接受 `0x` 前缀，大小写均可） |
| `FUN_0040D214` | `0x0040D214` | 分词器（分隔符见下） |
| `FUN_0040DBC8` | `0x0040DBC8` | 读一行（缓冲 `0x800`） |
| `FUN_0040D6FF` | `0x0040D6FF` | `fopen`，模式来自 `DAT_00435B0C="rt"` / `DAT_00435B08="wb"` |

分词分隔符：`DAT_00435B10` 处的字节是 **`b' ,'`**（空格 + 逗号），
另外代码里显式跳过 `\0`、`\t`、`\n`、`#`、`/`。

### 指令语法

`.config` 每行一条指令，参数用空格/逗号分隔。**所有字段都是小端 u32**：

| 助记符 | 文本形式 | 发出字节 | 语义 |
|---|---|---|---|
| `w` | `w <addr> <value>` | `addr, value` | 写寄存器 |
| `p` | `p <addr> <a> <b>` | `addr\|1, a, b` | 轮询：等 `(读回 & a) == b` |
| `n` | `n <value>` | `3, value` | 空操作/延时（单位见下） |
| `m` | `m <addr> <a> <b> [<or>]` | `addr\|2, a, b` | 读-改-写：`(读回 & a) \| or` |
| — | 文件结束 | `0xFFFFFFFF` | 终止符 |

**首字的低 2 位就是操作码**：

```
bit0=0 bit1=0  ->  write （2 个字）
bit0=1         ->  poll  （3 个字）
bit1=1         ->  mask  （3 个字）
首字 == 3      ->  nop   （2 个字）
首字 == 0xFFFFFFFF -> 结束
```

`0x00404810` 里可见的原始格式串（对应日志输出）：

```
write: 0x%08x = 0x%08x
poll:  0x%08x & 0x%08x = 0x%08x
nop:   0x%x
mask:  (0x%08x & 0x%08x) | 0x%08x, repeat=%d
stuff %d dummy zero(es)
skip unknown: %s
```

还有个特例：若 `mask` 的地址是 **`0xB801A60C`** 且是第一个 mask，
则多读一个 token 当 **repeat 次数**。

### 解密后的 blob 结构

```
[ 指令流 ]  连续的 u32，按上面的语法
[ 0xFFFFFFFF ]  终止符
[ 尾部 60~120 字节 ]
     +0x00  16 字节 头部：efabcdaa 13572468 a1b2c3d4 9092baba
            （注意其中 8 字节与 AES 密钥相同：bytes[4:12] == key[4:12]，
              开头 ef ab cd 像是密钥字节的置换，可能是密钥校验/派生标签）
     +0x10  N 字节 小字段，基本全零；usb_hwsetting.bin 是 80 00*9 23 a0
            （尾部 0x23A0 小端，疑似长度/校验标记）
     末尾   32 字节 签名/MAC
```

> 尾部的 MAC 算法**没逆出来**：它不是任何明显范围的 MD5/SHA。
> 重新生成 blob 时要**原样保留**这段尾部，否则设备大概会拒绝。

### 实测验证

把三个随包文件解密后按上述语法解码，结果**完全自洽**：

| 文件 | 总字数 | write | nop | mask | poll | end | 尾部 | 往返 |
|---|---|---|---|---|---|---|---|---|
| `usb_hwsetting.bin` | 296 | 128 | 12 | 0 | 0 | 1 | 60 B | ✅ 1184→1184 |
| `kylin_...2DDR3...` | 408 | 165 | 2 | 13 | 3 | 1 | 100 B | ✅ 1632→1632 |
| `kylin_...2DDR4...` | 472 | 177 | 3 | 21 | 6 | 1 | 120 B | ✅ 1888→1888 |

三个文件用**同一套语法**全部解开，`kylin` 那两个还用到了全部 4 种指令类型
（`mask`/`poll`），这是格式正确性的强证据。

再加一条 **AES 双射性铁证**：

```python
AES_ECB_encrypt(AES_ECB_decrypt(orig)) == orig   # 三个文件全部为 True
```

### 解码示例

```
write  0x1801A010 = 0x0000001F
write  0x1801A004 = 0x00000031
write  0x18000018 = 0x00000005
write  0x18000110 = 0x00000005
write  0x18000110 = 0x00000007
nop    0x1000                     ← 写完先等一下
write  0x18000110 = 0x00000003
...
mask   (0xFFFFFFF3 & 0x00000008) | 0x98007030   ← 读-改-写，DDR 训练常用
mask   (0xFFFFFFF3 & 0x00000009) | 0x98000050
poll   (0x9800E800 & 0x0000000F) == 0x0000000D  ← 等硬件就绪
...
end
```

这种"写 → nop → 再置位 → mask 改位域 → poll 等状态"的序列，
正是 DDR 控制器初始化 + PHY 训练的标准套路。

### 5.6 文本侧解析细节（`parse_line` 与 `swap`）

从 `boot_recoveryDlg.obj`（**未 strip，带完整符号与重定位表**）里把这两个函数逆出来了。

> ⚠️ 一个前提：`boot_recoveryDlg.obj` 与 `boot_recovery.exe` **不是同一次链接的结果**
> （obj 是 2016-12-08，exe 是 2017-02-14；`swap` 的字节在 exe 里只匹配前 8 字节，
> `parse_line` 的跳转表/字符串引用也对不上）。所以下面的结论以 **obj 的符号与重定位**为准，
> 并用 exe 的**字符串与导入表**交叉验证。好在两者要表达的逻辑是一致的。

#### `parse_line` —— UART 路径自己的 `.config` 解析器

签名（来自 obj 符号）：

```cpp
int CBoot_recoveryDlg::parse_line(char *line, unsigned int *out1, unsigned int *out2);
// __thiscall, ret 0xc (3 个参数 + this)
```

从 obj 的**重定位表**（16 条）可以精确看出它调用了什么：

| 重定位偏移 | 类型 | 目标符号 | 说明 |
|---|---|---|---|
| `+0x02` | dir32 | `??_C@_03IGFG@?5?0?7?$AA@` | **分隔符字面量** |
| `+0x19` | rel32 | `_strtok` | 第 1 次分词 |
| `+0x4e` | rel32 | `_strtok` | 第 2 次分词 |
| `+0x73` | rel32 | `_strtok` | 第 3 次分词 |
| `+0x9c` | rel32 | `_strtok` | 第 4 次分词 |
| `+0x61` `+0x82` `+0xab` | rel32 | `?atoh@CBoot_recoveryDlg@@QAEIPAD@Z` | 三次十六进制转换 |
| `+0xeb` | rel32 | `_printf` | `skip command: %s\n` |
| `+0x3b` `+0x42` | dir32 | `$L87430` / `$L87431` | **switch 跳转表 / 字节表** |
| `+0xe6` `+0xfc`… | dir32 | `skip command` 等字符串 | 错误/日志 |

**分隔符的真实字节**（从 obj 的 `.data` 里把那个 mangled 字符串读出来）：

```
??_C@_03IGFG@?5?0?7?$AA@  ->  20 2c 09 00   ==  ' ' ',' '\t' '\0'
```

`?5` = 空格、`?0` = 逗号、`?7` = Tab —— 三个字符，**没有 `=`**。

**分派逻辑**（obj `+0x028` 起）：

```
movsx eax, byte ptr [eax]     ; 取首字符
add   eax, -0x6d              ; 'm' = 0x6D 是基准
cmp   eax, 0xa                ; 11 个候选
ja    fail                    ; 超出范围 -> 返回 -1
xor   edx, edx
mov   dl, byte ptr [eax]      ; 字节表查表
jmp   dword ptr [edx*4]       ; 跳转表分派
```

即候选集是 **`'m'` 到 `'w'` 共 11 个字符**（`m n o p q r s t u v w`），
正好覆盖 `hwconfig` 用到的 `m`/`n`/`p`/`w` 四个助记符。

**三段分支体**（obj 偏移）：

| 偏移 | 行为 |
|---|---|
| `+0x046` | `strtok` → `atoh` → **写 `*out1`**；再 `strtok` → `atoh` → **写 `*out2`**；返回 0 |
| `+0x094` | `strtok` → `atoh` → 写 `*out2`；`*out1 = 0`；然后**特殊处理**（见下） |
| `+0x0E4` | `printf("skip command: %s\n")` 然后返回 -1 |

**`+0x094` 分支的两个关键常量**：

```
mov eax, [out2]           ; 取第二个值
cmp eax, 0x10000000
jae  L_shift
; --- 小于 0x10000000 ---
mov dword ptr [out1], 1   ; out1 置 1
xor eax, eax ; ret        ; 返回 0
L_shift:
shr eax, 0x1c             ; >> 28
mov [out1], eax
xor eax, eax ; ret
```

也就是：当第二个参数 `< 0x10000000` 时把第一个输出置 **1**，否则把第二个值
**右移 28 位**（取高 4 bit）当作第一个输出。这看起来是**给某个 `n`/`p` 类指令
把"延时/标志"编码进高位**用的——高 4 位存模式、低 28 位存数值。

#### `swap` —— 4 字节反转（`byteswap`）

`boot_recoveryDlg.obj` section 103，24 字节，**无重定位**，所以 obj 反汇编就是最终代码：

```asm
mov  eax, [esp+4]        ; src
mov  ecx, [esp+8]        ; dst
mov  dl, [eax+3]
mov  [ecx+0], dl         ; dst[0] = src[3]
mov  dl, [eax+2]
mov  [ecx+1], dl         ; dst[1] = src[2]
mov  dl, [eax+1]
mov  [ecx+2], dl         ; dst[2] = src[1]
mov  al, [eax+0]
mov  [ecx+3], al         ; dst[3] = src[0]
ret  8                   ; __stdcall，2 个参数
```

用 C 表达就是：

```c
void __stdcall swap(unsigned char *dst, const unsigned char *src) {  /* 注意参数顺序 */
    dst[0] = src[3]; dst[1] = src[2]; dst[2] = src[1]; dst[3] = src[0];
}
```

即 **`dst = byteswap(src)`**，纯粹的字节序反转。

它**不参与 `.config` → 二进制 的转换**（那条路径全用小端，见 §5.5），
而是给 **UART/YMODEM 路径**用的——串口上传的头部/CRC 字段需要大端。

#### 关于 `=` 号的结论

**`hwconfig` 的解析器完全不处理 `=`。**

- `parse_line` 用 `strtok` + 位置参数（第 1 个 token 是助记符，第 2、3 个是数值），
  分隔符只有 **空格、逗号、Tab**，重定位表里也没有任何涉及 `=` 的符号。
- `FUN_00404810`（USB 路径的转换器）用自定义分词器 `FUN_0040D214`，
  分隔符是 `b" ,"`，另外显式跳过 `\0` `\t` `\n` `#` `/`。
- 对 `boot_recovery.exe` 的 `.text` 做全量扫描，**`cmp <reg>, 0x3D` 指令数量为 0**。
  数据段里出现的 21 个 `=` 字节全部是指令立即数（如 `cmp eax, 0xC0000000` 里的 `3D`）
  或 `.rsrc` 里的图标像素，**没有一个是分隔符字符串**。

所以 `.config` 的语法是**位置式**的，不是 `key=value`：

```
w 0x1801a010 0x1f        ← 正确
addr=0x1801a010 val=0x1f ← 错误，会被当成 "skip unknown"
```

（有些 Realtek 文档里的 `.config` 确实写成 `名称 = 值` 的形式，那是**另一套工具/另一版格式**。）

#### `atoh` 的精确边界行为（已用 Unicorn 仿真逐位验证）

`CBoot_recoveryDlg::atoh` 在 exe 里位于 **`0x00404D60`，98 字节**，
而且**与 `boot_recoveryDlg.obj` section 107 的字节完全一致** —— 是同一次编译，
所以可以放心分析。完整反汇编：

```asm
00404D60  push esi
00404D61  mov  esi, [esp+8]     ; p
00404D65  xor  eax, eax         ; result = 0
00404D67  mov  cl, [esi]
00404D69  inc  esi
00404D6A  test cl, cl
00404D6C  je   404DC0           ; 空串 -> 返回 0
00404D6E  mov  edx, [esp+8]     ; ★ edx = 原始指针，整个循环只初始化这一次
00404D72  cmp  cl, '0'          ; ---- 循环头 ----
00404D75  jl   404D84
00404D77  cmp  cl, '9'
00404D7A  jg   404D84
00404D7C  movsx edx, cl         ; '0'..'9'
00404D7F  sub  edx, 0x30
00404D82  jmp  404DB4
00404D84  cmp  cl, 'a'
00404D87  jl   404D96
00404D89  cmp  cl, 'f'
00404D8C  jg   404D96
00404D8E  movsx edx, cl         ; 'a'..'f'
00404D91  sub  edx, 0x57
00404D94  jmp  404DB4
00404D96  cmp  cl, 'A'
00404D99  jl   404DA8
00404D9B  cmp  cl, 'F'
00404D9E  jg   404DA8
00404DA0  movsx edx, cl         ; 'A'..'F'
00404DA3  sub  edx, 0x37
00404DA6  jmp  404DB4
00404DA8  cmp  cl, 'X'
00404DAB  je   404DB2
00404DAD  cmp  cl, 'x'
00404DB0  jne  404DC0           ; 其它字符 -> 停，返回当前 eax
00404DB2  xor  eax, eax         ; ★ 'x'/'X' 清累加器（但不碰 edx！）
00404DB4  mov  cl, [esi]        ; ---- 提交 ----
00404DB6  shl  eax, 4
00404DB9  add  eax, edx
00404DBB  inc  esi
00404DBC  test cl, cl
00404DBE  jne  404D72           ; 下一个字符
00404DC0  pop  esi
00404DC1  ret
```

**用 Unicorn 直接仿真这段真实字节**（`spec/atoh_behaviour.py`），
逐用例得到下表 —— 这就是**手写 `.config` 时的实际容错范围**：

| 输入 | `atoh` 结果 | 说明 |
|---|---|---|
| `0x1801a010` | `0x1801a010` | 标准写法 |
| `1801a010` | `0x1801a010` | **不带 `0x` 也一样**（纯 hex 解析） |
| `0X1801A010` | `0x1801a010` | 大写 `X` + 大写数字都行 |
| `0x1f` | `0x1f` | 短值可以 |
| `0x` | `0` | 裸前缀返回 0 |
| `0x0x10` | `0x10` | 重复前缀无害 |
| `0xABCdef` | `0xABCDEF` | 大小写混用 OK |
| `1f ` | `0x1f` | 尾部空格无影响（`strtok` 已切掉；就算留着也会在空格处停下） |
| ` 1f` | **`0`** | ⚠️ **前导空格直接返回 0**（`atoh` 不跳空白） |
| `-0x1f` | **`0`** | ⚠️ 负号不支持 |
| `+1` | **`0`** | ⚠️ 正号也不支持 |
| `0xzz` | **`0`** | ⚠️ 前缀后非法 → **静默返回 0**，不报错 |
| `0x1801g010` | **`0x1801`** | ⚠️ **中间非法字符会静默截断**，取到哪算哪 |
| `g1801a010` | **`0`** | ⚠️ 首个字符非法 → 0 |
| `12g34` | **`0x12`** | ⚠️ 同上，后面的 `34` 被丢弃 |
| `0x100000000` | **`0`** | ⚠️ 33 bit → 静默回绕 |
| `0x1FFFFFFFF` | `0xFFFFFFFF` | 溢出回绕（不报错） |
| `0b101` | **`0xB101`** | ⚠️ **不是二进制！** `b` 是合法 hex 数字 |
| `010` | `0x10` | ⚠️ 不是八进制，是 hex 的 16 |
| `""` | `0` | 空串返回 0 |

**核心结论：没有任何错误检测。** 非法字符一律"取到哪算哪"或返回 0，
调用方**无法区分**"解析成功得到 0"和"解析失败得到 0"。

##### 🐛 顺带发现一个真 bug：前导 `x`/`X` 会泄漏指针值

`0x00404D6E` 处的 `mov edx, [esp+8]` 是**循环外唯一一次**给 `edx` 赋值，
而 `0x404DB2` 的 `xor eax,eax` **不碰 `edx`**。所以：

- `"0x10"` 安全：先遇到 `'0'`，`edx` 被设成 0，之后 `'x'` 清 `eax`，`add eax,edx` 加的仍是 0 ✅
- `"x10"` **不安全**：一上来就是 `'x'`，`edx` 还是**原始指针**！于是
  `eax = (pointer << 4) + 0x10`

实测（把同一个字符串放在不同地址）：

```
'x10' @0x200000 -> 0x20000010
'x10' @0x400000 -> 0x40000010
'x10' @0x555000 -> 0x55500010
'x10' @0x7f0000 -> 0x7f000010      ← 结果随内存布局变化 = 垃圾值
```

有趣的是这个 bug 会**自己消失**：`eax` 每个字符左移 4 位，
所以地址贡献在 **4 个以上 hex 字符**后被挤出 32 位：

```
'x'         -> 随地址变化
'x1'        -> 随地址变化
'x11'       -> 随地址变化
'x111'      -> 随地址变化
'x1111'     -> 稳定（地址已被移出）
'x11111111' -> 稳定
```

这也解释了为什么随包文件里从没暴露过它——真实地址都是 8 位 hex。

##### 参考实现（逐位精确）

`spec/atoh_reference.py` 是这个函数的精确 Python 模型，
并**用 Unicorn 仿真的真实字节做对拍**：

```
atoh model vs Unicorn emulation: 444/444 inputs agree
PASS -- reference model is bit-exact on all probes
```

444 个用例 = 44 个手工边界用例 + 400 个随机字符串（固定种子），全部一致。

> 注意：`atoh` 只负责把**一个 token** 转成数字。
> 真正的"位置式"语义由 `parse_line` / `FUN_00404810` 决定——
> 它们把第 1 个 token 当助记符，第 2、3 个 token 交给 `atoh`。
> 所以手写 `.config` 时，**数值部分**要遵守上表，**结构部分**要用位置式语法。

### 工具

配套工具 **`spec/hwconfig_tool.py`**：

```bash
python3 hwconfig_tool.py decode    <blob.bin>          # 解密 + 反汇编 + 显示尾部
python3 hwconfig_tool.py roundtrip <blob.bin>          # 解码→文本→重编码，验证无损
python3 hwconfig_tool.py encode    <in.config> <out.bin> [--encrypt]
python3 hwconfig_tool.py selftest                      # 三个随包文件全部校验
```

`selftest` 会验证每个文件的指令计数**和**往返一致性，全部通过。

### 结论：重写工具需要什么

要自己生成一个 hwsetting：

1. 写一份 `.config` 文本（`w`/`p`/`n`/`m` 指令）
2. `python3 hwconfig_tool.py encode my.config hwsetting_plain.bin`
3. 追加尾部（16 字节 header + 长度字段 + 32 字节 MAC）—— 建议直接复用现有 blob 的尾部
4. AES-128-ECB 加密 → 得到设备认的 `usb_hwsetting.bin`
5. 用 `0xF5` 写到 `0x1500000`

**不再需要 `GenKeyBag.exe`，也不需要 `.config` 样本** —— 格式已经查清。


---

## 6. 配置与镜像格式

### SYSTEM.ini
节：`[NAND FLASH TYPE] [MULTI FLASH TYPE] [INFORMATION] [SYSTEM] [1195_SYSTEM]`
关键项：`FLASH TYPE`(2=EMMC)、`FLASH COMBO TYPE`、`DDR TYPE`、`IMAGE PATH`、
`SINGLE MODE`、`BURN FACTORY`、`BURN SE STORAGE`、`ENCRYPTION KEY`、
`ONLY UPGRADE LAYOUT FIRMWARE`、`ONLY UPGRADE SECURE FIRMWARE`、`ONLY BURN EFUSE`、
`AUTO BURN`、`COMPARE DATA`、`NAS ENABLE`、`LK ENABLE`、`MAX USB CONNECTION`(8)、`GO DDR`。

### layout.txt（由 `LoadFlashLayout` @ rtumdfsampledlg.cpp:2748 解析）
```
target=<分区名> offset=<十六进制> size=<十六进制> [ name=<标签> ]
```
解析时用子串匹配 `target=` / `offset=` / `size=` / ` name=`，值为十六进制字符串。

### install.img
tar 风格容器，`FW_*` / `W_FW_*` 成员名（已确认列表见 `spec/protocol.json`
的 `image_layout.member_names_seen`），解包目录 `UnTarTmp`。

### factory.tar
包含 `layout.txt`、`env.txt`、`sn.txt`、`bootparam.h`、`enckey.bin`；
工具会解包、改 `writefactory=y`、重打包并重算头部（`factory_build_header`）。

### 随包的 `factory.tar` 是 **10240 字节全零**的占位文件
`Tempfile\factory.tar` 实测 10240 字节、非零字节数为 **0**，`tar` 打不开。
它是"空白 factory 区"模板；`Gen_blank_factory_tar_file` 会往里填 `layout.txt`/`env.txt` 等。
真正上机时工具会重新生成。

---

## 6.1 secure key / keybag / efuse 链路（本次拆解结果）

### 结论先说

**这台工具的主程序里根本没有 RSA。** `.text` 里与密码学相关的函数只有这几个（符号表核实）：

| 地址 | 函数 |
|---|---|
| `0x401780` | `AES128_ECB_decrypt` |
| `0x4017d0` | `AES128_CBC_encrypt_buffer` |
| `0x4018e0` | `AES128_CBC_decrypt_buffer` |
| `0x4019f0` | `crc32` |
| `0x429160` | `sysparam_crc32` |
| `0x42c4a0` | `tarlib::tarEntry::makeMD5`（tar 头校验，与安全无关） |

没有任何 `RSA_*` / `BN_*` / bignum / ModExp 符号。

### RSA 在哪里

RSA 公钥以 **PEM 文件**形式随包提供，在 `for_usb_mp_tool\keytemp\`：

| 文件 | 模数（1024 bit） | 用途 |
|---|---|---|
| `KRSAKeySetPub.pem` | `D10C231B...` | key set 验签/解封 |
| `KRSAKeySetPub1.pem` | `D10C231B...`（与上一个**完全相同**） | 同上 |
| `KRSAKeySetHeaderPub.pem` | `D854FB1D...`（不同） | key set **header** 验签 |

配套数据与工具：
- `key_set_final_enc.bin`（1408 字节，密文/签名块）
- `GenKeyBag.exe`、`ShowKeyBag.exe` —— **这两个 exe 并不在包内**（已确认：包内无此文件，
  `.rsrc` 段里也没有嵌入任何 `MZ`/`PE` 头）。主程序在运行时从安装目录/`for_usb_mp_tool`
  调用它们，必须由原始安装包（Inno Setup，`Includes\Jedi*.inc` 是安装脚本）释放。
- `openssl_win7\` / `openssl_winxp\` —— 完整 OpenSSL 1.0.x 发行版
  （`decrypted.txt` 里写着 "i am louis"，是别人留下的测试文件；`mykey.pem` 是配套示例私钥，
  模数 `E450819D...`，与三个 KRSA 公钥**都不匹配**，属示例残留）。

### 主程序自己做了什么

`Gen_storage_tar_file`（writefactory.cpp:161）与 `Gen_factory_tar_file`（writefactory.cpp:295）
的逻辑：

```
外部调用  ./GenKeyBag.exe        ← 生成原始安全 key（明文）
        ↓
内部函数  CBC_encryption_secure_key  0x42dc70   ← 用 AES-CBC 加密
        ↓
产物      key_bag_final_sing_cbc_enc.bin  (单份加密 key)
         key_bag_final_sig_enc.bin        (待签/已签的 key 包)
         key_bag_final_sig_dec.bin        (解出的 key 包)
         enckey.bin                       (最终写进 factory 区的加密 key)
         idx.txt / nowidx.txt / sn.txt    (key 索引、序列号)
```

关键反汇编证据：

- `0x431367` `push 0x5a2124` → `'./GenKeyBag.exe'`，紧接 `call 0x40d600`（`call_createProcess`）
- `0x42dc70` 所在函数的调用者之一是 `Gen_storage_tar_file`（writefactory.cpp:161），
  在 `0x4315aa` 调用 `CBC_encryption_secure_key`，入参是 `ebp+0x4c` 指向的 key 缓冲
- `CBC_encryption_secure_key` 的日志串说明了它的真实语义：
  ```
  0x5A22DC  icon[%d] : efuse - cbc encrypcion
  0x5A231C  cbc enc - read source code - raw key (enckey.bin) failr
  0x5A2358  cbc enc - move file failed , rename cbc_enckey.bin to enckey.bin
  0x5A23F0  cbc enc - delete file pc temp tmp se_storage enckey.bin failed
  0x5A2448  cbc enc - delete file pc temp tmp se_storage cbc_enckey.bin failed
  ```

**★ 决定性证据**：主程序**完全不引用** `key_set_final_enc.bin` / `KRSAKeySet*.pem` /
`openssl` / `.pem`（在 3.7MB 的 exe 里出现次数均为 **0**），只引用
`GenKeyBag`（4 次）和 `ShowKeyBag`（2 次）。
也就是说 **RSA 那套东西是外部 exe 的私事，主程序只负责"调它 + 搬运产物"**。

`CBC_encryption_secure_key` 内部：
```c
AES128_CBC_encrypt_buffer(out, in, len, (uchar*)param_2, &iv);   // 0x42dda5 调用
AES128_CBC_decrypt_buffer(chk, out, len, (uchar*)param_2, &iv);  // 0x42de7c 调用，回读自检
```
其中 `&iv` 就是紧挨在调用前压栈的字面量：
```
0x42DD96  push 0x607FB0   ->  0x42DDA5  call AES128_CBC_encrypt_buffer
0x42DE6D  push 0x607FB0   ->  0x42DE7C  call AES128_CBC_decrypt_buffer
```
而 `?iv@@3PAEA` 符号的地址正是 `0x5f7000 + 69552 = 0x607FB0` —— 该地址落在 `.data` 的
**BSS 部分**（`.data` 的 VSize 0x12140 > RawSize 0x6c00，超出部分加载时清零），
所以 **IV 就是 16 字节全零**，与 hwsetting 文件是同一套约定。

### enckey.bin 的处理方式（重要）

`CBC_encryption_secure_key` 处理的是 **`enckey.bin` 这份"原始 key"**，
把它加密后写成 `cbc_enckey.bin`，解密自检通过后再改名回 `enckey.bin`：

```
读 enckey.bin (raw key)
  → AES128_CBC_encrypt_buffer(..., key, zero_iv)  → cbc_enckey.bin
  → AES128_CBC_decrypt_buffer(..., key, zero_iv)  → 自检
  → 删除旧的 enckey.bin，把 cbc_enckey.bin 改名为 enckey.bin
```

**所以 `enckey.bin` 的 AES 密钥是"调用方传入的 key"**（`param_2`），
不是硬编码常量 —— 那个 key 由 `GenKeyBag.exe` 产出并交给工具。
这与 `usb_hwsetting.bin` 用固定常量密钥的情形不同，两者不要混为一谈。

### efuse 烧写

`efuse_burner`（key_write.cpp:686）用同一个 opcode `0xF9` 走两趟：

| 顺序 | 数据 | Type 字节 | 目标地址 |
|---|---|---|---|
| 1 | `FW_EFUSE_PROGRAMMER `（`Layout_Type[0x17]`） | `0x05` | `Layout_Type[0x17].memAddress` |
| 2 | `FW_EFUSE_VERIFY `（`Layout_Type[0x16]`） | `0x05` | `Layout_Type[0x16].memAddress` |

`FW_Efuse_Verify_Len == 0` 时打印 `"efuse_programmer.complete.enc length=0,pass burn efuse."` 直接跳过；
两趟之间没有额外握手，烧完 `Sleep(4000)`。

`se_storage_burner`（key_write.cpp:89）里还有一条不同的命令：
`WriteDevice(..., 0xF1, '\x03', 0, NULL, ...)` —— 这是"生成 ktee key"，
日志串是 `"secure burn : gen ktee key"`，随后读 `storage.tar` 用 `0xF4` 写入。

---

## 6.2 为什么"包里没有 GenKeyBag.exe 也能烧" —— 三道保险都会放行

**结论：你这套配置根本没走安全 key 那条路。** 三处独立的判定各自都会走"跳过"分支，
只要任一为真就绕开 keybag 流程；而你的系统三项全中。

### 证据一：SYSTEM.ini 三个开关全是 0

```ini
SINGLE MODE=0
BURN FACTORY=0                     ← 不烧 factory 区
BURN SE STORAGE=0                  ← 不烧安全存储
ENCRYPTION KEY=0
ONLY BURN EFUSE=0                  ← 不烧 efuse
ONLY UPGRADE SECURE FIRMWARE=0
ONLY UPGRADE LAYOUT FIRMWARE=0
COMPARE DATA=0
```

对应的 `check_burn_options`（`0x0040D920`，functioncode.cpp）是一个按 `param_2` 分派的 switch：

```c
case 0: return bOnly_burn_efuse | bReadSparemode | bReadmode | bOnly_upgrade_uboot | bSingle;
case 1: return (bOnly_burn_efuse | bReadSparemode | bReadmode | bSingle) & (bBurn_factory_area == 0);
case 2: return bBurn_factory_area;
case 3: uVar1 = bOnly_upgrade_secure_firmware | bOnly_upgrade_firmware;
```

`bBurn_factory_area = 0` 时，case 1 的 `& (bBurn_factory_area == 0)` 恒为真，
key/factory 分支直接被跳过。

### 证据二：efuse 长度判定（`efuse_burner` @0x410510）

```c
if (FW_Efuse_Programmer_Len == 0 && hi32(FW_Efuse_Programmer_Len) == 0) {
    SaveLogToThreadEditWindows(param_1,
        "efuse_programmer.complete.enc length=0,pass burn efuse.\r\n");
    return 100;                        // 直接成功返回，完全不碰设备
}
```

**你的日志里这一行出现了 24 次**（每次烧写一次）：

```
efuse_programmer.complete.enc length=0,pass burn efuse.
```

说明 `install.img` 里根本没有 `FW_EFUSE_PROGRAMMER ` 这个成员，
`Layout_Type[0x17].length` 保持 0，`efuse_burner` 第一件事就 `return 100`，
整个 `0xF9` 命令**一次都没发出去**。

### 证据三：factory 校验直接放行（`check_factory` @0x00432240）

```
0x43263C  cmp  dword ptr [ebp + 0x14], 0   ; writefactory flag
0x432640  je   0x43268A                    ; == 0 → 跳到放行分支
...
0x43268A  push 0x5A2D3C                    ; "check : writefactory != y\r\ndo not check secure key\r\n"
```

`factory.tar` 里的 `writefactory` 不是 `y` 时，**不检查 secure key**。
你的日志里同样出现 24 次：

```
check : writefactory != y
do not check secure key
full install - write blank factory.tar not include secure key- icon[0]
```

以及每次烧写的 `secure : 0`（73 次）—— 那是 `ReadFlashInfo` 里
`secure_option = IsDlgButtonChecked(0x409)` 的结果，未勾选即为 0。

### 汇总：你的实际执行路径

| 阶段 | 完整（带 key）路径 | 你的实际路径 |
|---|---|---|
| hwsetting / DDR | `0xF5` + `0xFA` | ✅ 一样（不需要 key） |
| bootloader | `0xF4` 逐成员 | ✅ 一样 |
| 系统镜像 | 按 layout.txt 分区 | ✅ 一样 |
| key_burner | 调 `GenKeyBag.exe` + AES-CBC | ⛔ **跳过** |
| factory 区 | 写含 key 的 factory.tar | ⛔ **跳过**（改写 blank factory.tar） |
| efuse | `0xF9` 两趟 | ⛔ **跳过**（length=0 直接 return 100） |

**所以 `GenKeyBag.exe` 缺失对你毫无影响**：它只在你要烧安全 key / se_storage / efuse
时才被调用，而这三项你全关。你日志里 24 次烧写没有一次触发它。

反过来要小心：**哪天把 `BURN FACTORY=1`、`BURN SE STORAGE=1` 或 `ONLY BURN EFUSE=1`
打开，工具会立刻因为找不到 `GenKeyBag.exe` 而失败**
（报 `CALL_PROCESS_GEN_SINGLE_KEY_FAIL` / `GEN_SINGLE_KEY_FAIL`）。

### 旁证：这个包本来就不是量产全功能版

`for_usb_mp_tool\` 里还缺 `config.txt`（主程序在找 `\config.txt`），
`envgroup.txt` 只有 1 个字节（内容就是字符 `1`）。
说明这是一个**"只烧固件、不烧 key"的精简发布包** —— 开发/维修够用；
量产线要做 key 个性化时才需要补齐整套（`GenKeyBag.exe`、`ShowKeyBag.exe`、
`config.txt`，以及 `key_set_final_enc.bin` 的正确用法）。

---

### 没能闭合的一环（如实说明）

`key_set_final_enc.bin` 的**外层密钥**没能解出：

- 它 1408 = 11×128 字节；128 字节正好是 1024-bit RSA 的块长，但每个块
  按大端/小端取整后**多数 ≥ 公钥模数 n**（11 块里只有 7~8 块小于 n），
  说明它不是"整块裸 RSA"。
- 用三个 KRSA 公钥做 `block^65537 mod n`，结果既不是 `00 01`(PKCS#1 v1.5 签名)
  也不是 `00 02`(PKCS#1 加密) 结构。
- 用包内唯一可用私钥 `mykey.pem` 做私钥运算，输出仍是高熵、无可读结构。
- 该文件里有 14 个**完全相同的 16 字节块**（偏移 0x20,0x40,0x50,0x80,0xB0 起…），
  这是 CBC/结构性重复的特征，但不是任何已知 key（含 USB AES key、公钥模数切片）的
  `E(0^16)`，所以不是"零块 ECB"。

**判断**：真正解 `key_set_final_enc.bin` 的逻辑在缺失的 `GenKeyBag.exe` 里，
主程序只负责调用它并搬运产物。要完全闭合这条链，需要拿到原始安装包里的
`GenKeyBag.exe` / `ShowKeyBag.exe` 再做一次逆向。

---

## 7. 其它固件 blob

| 文件 | 架构 | 作用 |
|---|---|---|
| `goddr\DeviceToEmmc.bin` (2552B) | ARM32 | device 模式引导桩：`r0=0x1500000` + memcpy 循环 + `bx` 跳转 |
| `goddr\DeviceToNand.bin` (2552B) | ARM32 | NAND 引导桩 |
| `goddr\DeviceToNor.bin` (264B) | ARM32 | NOR 引导桩 |
| `goddr\DeviceToEmmcAdjSpeed.bin` (244B) | ARM32 | eMMC 时钟调速 |
| `Tempfile\nand_erase_dvrboot.exe.bin` (686KB) | **ARM64** | NAND 擦除/驱动引导负载 |
| `Tempfile\bootloader.tar` (1.2MB) | — | `bl31.bin fsbl.bin hw_setting.bin tee.bin uboot.bin` |
| `Tempfile\1295_default_env.txt` | — | u-boot 默认环境变量 |
| `for_usb_mp_tool\keytemp\*` | — | key bag 生成（KRSAKeySet*.pem、key_set_final_enc.bin、自带 openssl_win7） |

---

## 8. 交付物清单

```
w2_reverse/
├─ spec/
│  ├─ protocol.json          机器可读协议规格（本文档的结构化版本）
│  ├─ PROTOCOL.md            本文档
│  ├─ rtk_usb_protocol.h     C 头文件：全部结构体/常量/枚举
│  └─ rtk_flash_client.py    Python 参考实现（CBW/CSW 传输层 + 烧写流程骨架）
├─ decompiled/               318 个业务函数反编译 C 代码（文件名 = 地址_函数名.c）
└─ index/
   ├─ functions.tsv          14145 个函数（地址/名/大小/thunk）
   ├─ func_src.tsv           9198 个函数 → 源码文件:行 映射
   ├─ symbols.tsv            90754 个符号
   ├─ prototypes.tsv         14145 个函数原型
   ├─ types_full.txt         全部结构体/联合/枚举布局（含字段偏移）
   ├─ strings.tsv            6049 条字符串（含地址）
   └─ sourcemap.tsv          789 个源文件
```

---

## 9. 重写建议

1. **驱动层**：设备是普通厂商 USB 接口，Windows 下可继续用 `rtumdfdrv`+`CreateFile`，
   或改用 WinUSB/libusb；Linux 下用 libusb 直接 bulk transfer 即可，不需要写内核驱动。
2. **协议层**：照抄 CBW/CSW 帧（43/50 字节），注意 `bCBWCBLength=28`、
   `bCSWStatus` 在 +13、`iIndicator` 的首/中/末片编码。
3. **务必保留**：CRC32 校验、200 次重试 / 200ms / 20s 超时、
   NAND 坏块重映射（`CSW_STAT_WFAIL` 分支）、`0xFA` DDR enable 后的 1500ms 等待。
4. **数据准备**：`usb_hwsetting.bin` 用固定 AES 密钥；`bootloader.tar` 成员按上表 LBA 顺序写；
   `install.img` 按 `layout.txt` 分区表写；factory 区上限 `0x200000`。
5. **先用日志回归**：`log\debug_log\*.txt` 里有历史成功烧写的完整逐包记录
   （每片 LBA、长度、iIndicator、CSW 状态），可以直接拿来对拍你的新实现。

---

## 10. 已确认 / 未确认

**已确认（有反汇编或日志证据）**
- CBW/CSW 帧格式与长度、signature/tag、`iIndicator` 编码、状态字节偏移 13
- 全部 11 个命令字及其处理函数与源码行
- `_CBWCB` / `_FlashInfo` / `type_deviceInfo` / `_BB_t` / `_BBT_List` 结构布局
- AES 密钥、hwsetting 加密文件（零 IV 实测解密成功）
- bootloader 成员 → LBA 映射（与日志逐项吻合）
- layout.txt 字段语法、factory 区上限与起始页
- **`Layout_Type[0..23]` 全部 24 个成员名，及与 `type_deviceInfo.FW_*_Len` 的完整对应表（§4.1）**
- **主程序内不含 RSA：只有 AES-128 ECB/CBC + CRC32 + MD5；RSA 在外部 `GenKeyBag.exe`**
- **keybag 加密的 IV = 全零（`?iv@@3PAEA` @ 0x607FB0 落在 .data 的 BSS 区，加载即清零）**
- **efuse 用 `0xF9`/type `0x05` 走两趟：`FW_EFUSE_PROGRAMMER `(0x17) 再 `FW_EFUSE_VERIFY `(0x16)**
- **随包 `Tempfile\factory.tar` 是 10240 字节全零占位文件**

**未完全确认**
- `bCSWStatus` 各值的完整状态机（`WKEYFAIL`/`WKEYPASS`/`RKEYFAIL` 分支未逐一走通）
- `type_deviceInfo` 中 `FW_*_Len` 的语义（哪个成员对应镜像里哪个 `FW_*`）需结合 `install.img` 实测
- `Factory`/`efuse` 的密钥交换细节（`keytemp` 下的 RSA 公钥与 `key_set_final_enc.bin`）
- `nand_erase_dvrboot.exe.bin` 是 ARM64 负载，未做指令级分析

---

## 附录 A：2026-10-23 真机抓包修正（实现以本节为准）

用 USBPcap 抓到原工具刷写这块板子的**完整双向流量**后，修正了正文里两处
从反编译推断出的错误结论：

1. **`0xFA` DDR enable 不是空操作。** 原工具在 hwsetting 的 CSW 之后先
   `Sleep(1500ms)`（`usb_hw_setting_burner` 里的 `Sleep(0x5DC)`），
   **再发一条正常 CBW**：`opcode=0xFA type=0x06 dlen=5 iIndicator=3`，
   载荷就是 5 字节 ASCII `"test\0"`，设备在 1ms 内回 `0x00` PASS。
   不发这条帧、或发早了（比如 hwsetting CSW 后 1ms 就发），设备会收下
   hwsetting 但**拒收后续 WRITE 的载荷**（实测到 NAK 70 秒、以及永远不回
   CSW 两种表现，最终 `CSW retry exhausted`）。
2. **设备对每一片 256 KiB 都回 50 字节 CSW**（黄金抓包 1378 CBW → 1377 CSW，
   状态全 `0x00`），片间同步问答，CSW 延迟中位 7.7ms。不存在“只在一轮末尾
   回一次”的流控；主机侧必须每片都读 50 字节，且用同步 `ReadFile`
   （原工具没有后台读线程；常驻 4096B 读会与 256KB 写抢同一个 UMDF 句柄）。

### factory 区格式（不是裸 tar）

```
[10 KiB 对齐的 tar：tmp/factory/(目录) + tmp/factory/env.txt + tmp/factory/layout.txt]
[512 字节：tar 首块副本，尾部补丁 +0x1F8=归档长度(u32 LE)，+0x1FC="RTK\0"，并重算 tar 校验和]
[1024 字节 0]
```

- U-Boot 靠 `"RTK\0"` magic 判定“有 factory 数据”；没有它会在串口打印
  `[FAC] No factory data in eMMC`，随后 env 读不到、FW 表加载失败、停在 `BPI-W2>`。
- 原工具写两份：LBA 0x1100（144,896 B）和 0x2100（145,408 B）。
- 镜像里的 `omv/factory.tar` 可能有两种命名（根相对 `env.txt` 或已带
  `tmp/factory/` 前缀），**只能补一层前缀**，否则 U-Boot 找不到 env.txt。

### 大包（>2 GB / >4 GB 成员）

原工具是 32 位：它加载镜像时要一次性分配“分区总大小”的虚拟内存
（实测 `virtual totalsize:3745758720` → `GetLastError:8`），7.8 GB 包直接失败。
重写版按 2 MiB 一块从 tar 流式读取，tar 成员偏移/大小全部用 u64，
单成员 7.0 GB 也可以刷。
