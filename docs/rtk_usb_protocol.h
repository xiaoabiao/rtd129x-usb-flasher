/*
 * rtk_usb_protocol.h
 *
 * Reverse-engineered protocol definitions for the Realtek RTD129x (RTD1295/RTD1195)
 * USB download tool ("rtumdfsample.exe").
 *
 * Source of truth:
 *   rtumdfsample.exe  SHA-256 c29ba32b5ce1e5d0393bab777fe39d8405161e871dd0c2cf1766ee74f18a0bd0
 *   rtumdfsample.pdb  GUID 18e2c3bf-fc28-d145-ac12-305158217c32, age 15
 *
 * Every offset below is confirmed by either the PDB type stream or by disassembly
 * at the addresses cited in the comments.
 */
#ifndef RTK_USB_PROTOCOL_H
#define RTK_USB_PROTOCOL_H

#include <stdint.h>

#pragma pack(push, 1)

/* ------------------------------------------------------------------ */
/* USB device identity                                                 */
/* ------------------------------------------------------------------ */
#define RTK_USB_VID               0x0BDA
#define RTK_USB_PID               0x1195

/* {7B56A5D6-CD10-4410-9F59-9A5E71269882} - SetupDi device interface GUID.
 * Read from .rdata at VA 0x00596AC0. */
#define RTK_DEVINTERFACE_GUID_STR "{7B56A5D6-CD10-4410-9F59-9A5E71269882}"

/* {23FA4AD3-B0C4-40C8-BDDA-28F67F2E70CA} - driver class GUID (rtumdfdrv64.inf) */
#define RTK_DRIVER_CLASS_GUID_STR "{23FA4AD3-B0C4-40C8-BDDA-28F67F2E70CA}"

/* Driver-side maximum for a single USB request (from the debug log / driver). */
#define RTK_MAX_USB_TRANSFER      0x20000u   /* 128 KiB */

/* ------------------------------------------------------------------ */
/* CBW / CSW framing                                                   */
/* ------------------------------------------------------------------ */
#define CBW_SIGNATURE             0x43425355u  /* 'USBC' little-endian */
#define CBW_TAG                   0x12345678u
#define CBW_FLAGS_READ            0x80u        /* device -> host */
#define CBW_FLAGS_WRITE           0x00u        /* host -> device */

#define CBW_FRAME_LENGTH          43u          /* push 0x2b at 0x4049d2 */
#define CBWCB_OFFSET              0x0Fu
#define CBWCB_LENGTH              28u          /* 0x1c stored at frame+0x0e */

#define CSW_SIGNATURE             0x53425355u  /* 'USBS' little-endian */
#define CSW_FRAME_LENGTH          50u          /* cmp,0x32 read at 0x405f77 */
#define CSW_TAG_OFFSET            0x04u
#define CSW_STATUS_OFFSET         13u          /* proven: 0x405f7a frame=ebp-0x9c, status=ebp-0x8f */

/* iIndicator (CBW +0x0D): low nibble = chunk position, high nibble = mode flags.
 * Built at 0x40647e..0x4064d9 as ((p16 & 3) | (p17 << 2)) << 4 | spare. */
#define CBW_IND_FIRST             0x1u
#define CBW_IND_MIDDLE            0x0u
#define CBW_IND_LAST              0x3u
#define CBW_IND_BUSY              0x2u

/* bCSWStatus values (PDB enum CSW_STAT_TABLE) */
typedef enum {
    CSW_STAT_PASS        = 0,
    CSW_STAT_FAIL        = 1,   /* retry */
    CSW_STAT_BUSY        = 2,   /* keep polling */
    CSW_STAT_WFAIL       = 3,   /* NAND bad block -> remap */
    CSW_STAT_WKEYFAIL    = 4,
    CSW_STAT_WKEYPASS    = 5,
    CSW_STAT_RKEYFAIL    = 6
} CSW_STAT_TABLE;

/* Sense/channel bytes observed at 0x5973xx / CSW sense field */
#define RTK_SENSE_FPGA_BUSY       0x00
#define RTK_SENSE_PASS            0x01
#define RTK_SENSE_FAIL            0x02
#define RTK_SENSE_READ_SPARE      0x09

/* Retry policy (WriteDevice @ 0x4057d0) */
#define RTK_CSW_MAX_RETRY         200
#define RTK_CSW_RETRY_SLEEP_MS    200
#define RTK_CSW_TIMEOUT_SEC       20

/* ------------------------------------------------------------------ */
/* Command opcodes (CBWCB.OPCode)                                      */
/* ------------------------------------------------------------------ */
typedef enum {
    RTK_OP_SE_STORAGE        = 0xF1,  /* se_storage_burner      key_write.cpp:89    */
    RTK_OP_SINGLE_STATUS     = 0xF2,  /* single_burner          single_write.cpp:32 */
    RTK_OP_NAND_WRITE        = 0xF3,  /* nand_burner            nand_write.cpp:32   */
    RTK_OP_WRITE             = 0xF4,  /* WriteDevice            dev_api.cpp:104     */
    RTK_OP_USB_HWSETTING     = 0xF5,  /* usb_hw_setting_burner  rtumdfsampledlg.cpp:4643 */
    RTK_OP_WRITE_VERIFY      = 0xF6,  /* TestWriteDevice        dev_api.cpp:828     */
    RTK_OP_EFUSE_BURN        = 0xF9,  /* efuse_burner           key_write.cpp:686   */
    RTK_OP_DDR_ENABLE        = 0xFA,  /* usb_hw_setting_burner (type byte 0x06)     */
    RTK_OP_SINGLE_DATA       = 0xFB,  /* single_burner                              */
    RTK_OP_READ_VERIFY       = 0xFC,  /* TestRead/WriteDevice                       */
    RTK_OP_SENSE             = 0x1C   /* TestReadDevice         dev_api.cpp:1079    */
} RTK_OPCODE;

/* Sub-command / type byte for RTK_OP_DDR_ENABLE */
#define RTK_TYPE_DDR_ENABLE       0x06u
#define RTK_TYPE_WRITE_CHUNK      0x01u

/* flashType in CBWCB / FlashInfo */
#define RTK_FLASH_NAND            0u
#define RTK_FLASH_NOR             1u
#define RTK_FLASH_EMMC            2u

/* ------------------------------------------------------------------ */
/* CBWCB - command block, 28 bytes (PDB struct _CBWCB)                 */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  OPCode;               /* +0x00  top-level opcode 0xF1..0xFC      */
    uint8_t  Type;                 /* +0x01  sub-command / flags              */
    uint32_t LogicalBlockAddress;  /* +0x02  512B sector (bootloader) or byte */
    uint8_t  NandEccBit;           /* +0x06                                   */
    uint8_t  flashType;            /* +0x07  0=NAND 1=NOR 2=EMMC              */
    uint16_t PageSize;             /* +0x08                                   */
    uint32_t blockSize;            /* +0x0A                                   */
    uint32_t nandSize;             /* +0x0E                                   */
    uint16_t Spare;                /* +0x12  ==0x79 -> high byte = remap idx  */
    uint32_t WriteSpecialSize;     /* +0x14                                   */
    uint32_t CRC32;                /* +0x18  CRC32 of this chunk payload      */
} RTK_CBWCB;                       /* sizeof == 28 */

/* ------------------------------------------------------------------ */
/* CBW - Command Block Wrapper, 43 bytes                               */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t signature;            /* +0x00 0x43425355 'USBC'                 */
    uint32_t tag;                  /* +0x04 0x12345678                        */
    uint32_t dataTransferLength;   /* +0x08 payload length                    */
    uint8_t  flags;                /* +0x0C 0x80 = read, 0x00 = write          */
    uint8_t  iIndicator;           /* +0x0D chunk position | mode flags       */
    uint8_t  cbwcbLength;          /* +0x0E 28                                */
    RTK_CBWCB cbwcb;               /* +0x0F                                   */
} RTK_CBW;                         /* sizeof == 43 */

/* ------------------------------------------------------------------ */
/* CSW - Command Status Wrapper, 50 bytes                              */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t signature;            /* +0x00 0x53425355 'USBS'                 */
    uint32_t tag;                  /* +0x04 0x12345678                        */
    uint32_t dataResidue;          /* +0x08                                   */
    uint8_t  sense;                /* +0x0C                                   */
    uint8_t  status;               /* +0x0D CSW_STAT_TABLE                    */
    uint8_t  reserved[36];         /* +0x0E .. +0x31                          */
} RTK_CSW;                         /* sizeof == 50 */

/* ------------------------------------------------------------------ */
/* Flash geometry (PDB struct _FlashInfo), size 64                     */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  flashType;            /* +0x00 */
    uint32_t nandSize;             /* +0x04 MB */
    uint32_t blockSize;            /* +0x08 KB */
    uint32_t pageSize;             /* +0x0C */
    uint8_t  eccBit;               /* +0x10 */
    uint32_t start_addr;           /* +0x14 */
    int64_t  trans_size;           /* +0x18 */
    uint32_t write_special_count;  /* +0x1C */
    int64_t  cover_value;          /* +0x20 */
    uint16_t spare_value;          /* +0x28 */
    uint32_t once_trans_max_size;  /* +0x2C */
    int32_t  secure_option;        /* +0x30 */
    int32_t  go_or_jump_opetion;   /* +0x34 */
    uint32_t read_data_range;      /* +0x38 */
    uint32_t read_spare_count;     /* +0x3C */
} RTK_FLASH_INFO;                  /* sizeof == 64 */

/* ------------------------------------------------------------------ */
/* NAND bad-block bookkeeping                                          */
/* ------------------------------------------------------------------ */
typedef struct {                   /* size 8 */
    uint16_t BB_die;
    uint16_t bad_block;
    uint16_t RB_die;
    uint16_t remap_block;
} RTK_BB;                          /* PDB: _BB_t / BB_t */

typedef struct {                   /* size 12 */
    RTK_BB  *BBT;
    long     rmp_blk_used_count;
    long     rmp_blk_max_count;
} RTK_BBT_LIST;                    /* PDB: _BBT_List */

/* ------------------------------------------------------------------ */
/* Layout descriptor used while writing install.img partitions         */
/* ------------------------------------------------------------------ */
typedef struct {                   /* size 40 */
    const char *target;
    int64_t     length;
    uint8_t    *buffer;
    int64_t     addrOffset;
    uint32_t    memAddress;        /* in Mbr/Part variants: int64 partitionSize */
} RTK_LOAD_LAYOUT_DATA;            /* PDB: st_LoadLayoutData / ...Mbr / ...Part */

/* ------------------------------------------------------------------ */
/* Layout_Type[24] member index -> install.img tar member name         */
/*                                                                     */
/* Layout_Type is a 24 x sizeof(RTK_LOAD_LAYOUT_DATA) global array in  */
/* .data, built by the dynamic initializer ??__ELayout_Type@@YAXXZ.    */
/* set_device_info_value @0x426BD0 copies Layout_Type[n].length into   */
/* the matching type_deviceInfo.FW_*_Len field.                        */
/*                                                                     */
/* NOTE: every name ends with a trailing space, and layout.txt parsing */
/* matches the full string including that space.                       */
/* ------------------------------------------------------------------ */
typedef enum {
    RTK_LAYOUT_FW_KERNEL              = 0x00,  /* "FW_KERNEL "            -> FW_Kernel_Len            */
    RTK_LAYOUT_FW_RESCUE_DT           = 0x01,  /* "FW_RESCUE_DT "         -> FW_Rescue_DT_Len         */
    RTK_LAYOUT_FW_KERNEL_DT           = 0x02,  /* "FW_KERNEL_DT "         -> FW_Kernel_DT_Len         */
    RTK_LAYOUT_FW_RESCUE_ROOTFS       = 0x03,  /* "FW_RESCUE_ROOTFS "     -> FW_Rescue_RootFS_Len     */
    RTK_LAYOUT_FW_KERNEL_ROOTFS       = 0x04,  /* "FW_KERNEL_ROOTFS "     -> FW_Kernel_RootFS_Len     */
    RTK_LAYOUT_FW_NAS_RESCUE_KERNEL   = 0x05,  /* "FW_NAS_RESCUE_KERNEL " -> FW_Nas_Rescue_Kernel_Len */
    RTK_LAYOUT_FW_NAS_RESCUE_DT       = 0x06,  /* "FW_NAS_RESCUE_DT "     -> FW_Nas_Rescue_DT_Len     */
    RTK_LAYOUT_FW_NAS_RESCUE_ROOTFS   = 0x07,  /* "FW_NAS_RESCUE_ROOTFS " -> FW_Nas_Rescue_RootFS_Len */
    RTK_LAYOUT_FW_AKERNEL             = 0x08,  /* "FW_AKERNEL "           -> FW_Akernel_Len           */
    RTK_LAYOUT_FW_TEEKERNEL           = 0x09,  /* "FW_TEEKERNEL "         -> FW_Teekernel_Len         */
    RTK_LAYOUT_FW_BL31                = 0x0A,  /* "FW_BL31 "              -> FW_Bl31_Len              */
    RTK_LAYOUT_FW_P_UBOOT             = 0x0B,  /* "FW_P_UBOOT "           -> FW_Puboot_Len            */
    RTK_LAYOUT_FW_DALOGO              = 0x0C,  /* "FW_DALOGO "            -> FW_Dalogo_Len            */
    RTK_LAYOUT_FW_DILOGO              = 0x0D,  /* "FW_DILOGO "            -> FW_Dilogo_Len            */
    RTK_LAYOUT_FW_CILOGO1             = 0x0E,  /* "FW_CILOGO1 "           -> FW_Cilogo1_Len           */
    RTK_LAYOUT_FW_FWTBL               = 0x0F,  /* "FW_FWTBL "             -> FW_Table_Len             */
    RTK_LAYOUT_FW_CONFIG              = 0x10,  /* "FW_CONFIG "            -> FW_Config_Len            */
    RTK_LAYOUT_FW_PROFILE             = 0x11,  /* "FW_PROFILE "           -> FW_Profile_Len           */
    RTK_LAYOUT_FW_GOLD_KERNEL         = 0x12,  /* "FW_GOLD_KERNEL "       -> FW_Gold_Kernel_Len       */
    RTK_LAYOUT_FW_GOLD_RESCUE_DT      = 0x13,  /* "FW_GOLD_RESCUE_DT "    -> FW_Gold_Rescue_DT_Len    */
    RTK_LAYOUT_FW_GOLD_ROOTFS         = 0x14,  /* "FW_GOLD_ROOTFS "       -> FW_Gold_RootFS_Len       */
    RTK_LAYOUT_FW_GOLD_AKERNEL        = 0x15,  /* "FW_GOLD_AKERNEL "      -> FW_Gold_Akernel_Len      */
    RTK_LAYOUT_FW_EFUSE_VERIFY        = 0x16,  /* "FW_EFUSE_VERIFY "      -> FW_Efuse_Verify_Len      */
    RTK_LAYOUT_FW_EFUSE_PROGRAMMER    = 0x17,  /* "FW_EFUSE_PROGRAMMER "  -> FW_Efuse_Programmer_Len  */
    RTK_LAYOUT_COUNT                  = 24
} RTK_LAYOUT_INDEX;

/* efuse is written with opcode 0xF9 / type 0x05, in this order. */
#define RTK_EFUSE_TYPE            0x05u

/* AES-CBC IV shared by hwsetting and keybag encryption.
 * PDB symbol ?iv@@3PAEA lives at 0x00607FB0, inside the BSS part of .data
 * (VSize 0x12140 > RawSize 0x6C00), so it is 16 zero bytes at runtime. */
extern const uint8_t RTK_AES_IV_ZERO[16];

/* ------------------------------------------------------------------ */
/* sysparam on-flash header (PDB sysparam_phys)                        */
/* ------------------------------------------------------------------ */
#define RTK_SYSPARAM_MAGIC        0x53595350u  /* 'PSYS' */
typedef struct {
    uint32_t magic;
    uint32_t crc32;
    uint32_t flags;
    uint16_t namelen;
    uint16_t datalen;
    uint8_t  namedata[];
} RTK_SYSPARAM_PHYS;

/* ------------------------------------------------------------------ */
/* Bootloader members -> start LBA (verified against debug_log)        */
/*   next_lba = lba + ceil(size / 512)                                 */
/* ------------------------------------------------------------------ */
#define RTK_LBA_HW_SETTING        256u    /* hw_setting.bin  3200 B  */
#define RTK_LBA_UBOOT             263u    /* uboot.bin     604128 B  */
#define RTK_LBA_FSBL              1443u   /* fsbl.bin       72544 B  */
#define RTK_LBA_TEE               1585u   /* tee.bin       507616 B  */

/* usb_hwsetting blob is written at a raw byte address, not a sector index. */
#define RTK_ADDR_USB_HWSETTING    0x1500000u

/* factory area */
#define RTK_FACTORY_START_PAGE_A  4352u   /* 0x220000 */
#define RTK_FACTORY_START_PAGE_B  8448u   /* 0x420000 */
#define RTK_FACTORY_MAX_SIZE      0x200000u

/* ------------------------------------------------------------------ */
/* AES key material embedded in the tool (RTK_AES_KEY_USB)             */
/* ------------------------------------------------------------------ */
extern const uint8_t RTK_AES_KEY_USB[16];   /* abcdef1213572468a1b2c3d49090babe */

#pragma pack(pop)

#endif /* RTK_USB_PROTOCOL_H */
