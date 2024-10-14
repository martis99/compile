#include <memory.h>
#include <stdint.h>
#include <stdio.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// ELF INDENTIFICATION
// Magic number
#define EI_MAG 0x7F454C46 //.ELF

// 32-bit/64-bit format
#define EI_CLASS_32 0x01 // 32-bit
#define EI_CLASS_64 0x02 // 64-bit

// Little/Big endian
#define EI_DATA_LE 0x01 // Little Endian
#define EI_DATA_BE 0x02 // Big Endian

// Version of ELF
#define EI_VERSION 0x01 // 1

// Operating System Application Binary Interface
#define EI_OSABI_SYSTEM_V 0x00 // Unix System V

// ABI bersion
#define EI_OSABI_ABIVERSION 0x00 // 0

// Padding bytes
#define EI_PAD0 0x00 // 0
#define EI_PAD1 0x00 // 0
#define EI_PAD2 0x00 // 0
#define EI_PAD3 0x00 // 0
#define EI_PAD4 0x00 // 0
#define EI_PAD5 0x00 // 0
#define EI_PAD6 0x00 // 0

typedef enum elf_type
{
	ELF_TYPE_EXEC = 0x02,
} elf_type_t;

typedef enum elf_machine
{
	ELF_MACHINE_AMD_X86_64 = 0x3E
} elf_machine_t;

#define BYTE_LE(_v, _i) (u8)((_v) >> (8 * (_i)) & 0xFF)
#define BYTE_BE(_v, _i) (u8)((_v) >> (8 * (sizeof(_v) - 1 - (_i))) & 0xFF)

typedef enum elf_flag
{
	ELF_FLAG_NONE,
} elf_flat_t;

// Program header
typedef enum ph_type
{
	PH_TYPE_LOAD = 0x01,
} ph_type_t;

typedef enum ph_flag
{
	PH_FLAG_X = 0x01,
	PH_FLAG_W = 0x02,
	PH_FLAG_R = 0x04,
} ph_flag_t;

// Section header
typedef enum sh_type
{
	SH_TYPE_UNKNOWN = 0x00,
	SH_TYPE_PROGBITS = 0x01,
	SH_TYPE_STRTAB = 0x03,
} sh_type_t;

typedef enum sh_flag
{
	SH_FLAG_NONE = 0x00,
	SH_FLAG_ALLOC = 0x02,
	SH_FLAG_EXECINSTR = 0x04,
} sh_flat_t;

typedef struct elf_header
{
	u32 imag;
	u8 iclass;
	u8 idata;
	u8 iversion;
	u8 iosabi;
	u8 iabiversion;
	u8 ipad0;
	u16 ipad1;
	u32 ipad2;
	u16 type;
	u16 mashine;
	u32 version;
	u64 entry; // Address of the entry point
	u64 phoff;
	u64 shoff; // Section header table offset
	u32 flags;
	u16 ehsize;
	u16 phentsize;
	u16 phnum; // Number of entries in the program header table
	u16 shentsize;
	u16 shnum;    // Number of entries in the section header table
	u16 shstrndx; // Index of the section header table entry that contains the section names
} __attribute__((packed)) elf_header_t;

typedef struct program_header
{
	u32 type;
	u32 flags;
	u64 offset;
	u64 vaddr; // Virtual address
	u64 paddr; // Physical address
	u64 filesz;
	u64 memsz;
	u64 align;
} __attribute__((packed)) program_header_t;

typedef struct section_header
{
	u32 name;
	u32 type;
	u64 flags;
	u64 addr;
	u64 offset;
	u64 size;
	u32 link;
	u32 info;
	u64 addralign;
	u64 entsize;
} __attribute__((packed)) section_header_t;

typedef struct exe
{
	elf_header_t elf;
	program_header_t program[2];
	union
	{
		struct
		{
			u8 code[0x0a];
			u8 strs[0x11];
		};
		u8 data[0x20];
	};
	section_header_t section[3];
} __attribute__((packed)) exe_t;

static void print_bytes(void *ptr, u16 size)
{
	u8 *bytes = ptr;
	printf("%08X  ", 0);
	for (u16 i = 0; i < size; i++)
	{
		printf("%02x ", bytes[i]);
		if (i > 0 && (i + 1) % 16 == 0)
		{
			if (i + 1 < size)
			{
				printf("\n%08X  ", i + 1);
			}
		}
		else if (i > 0 && (i + 1) % 8 == 0)
		{
			printf(" ");
		}
	}

	printf("\n");
}

static void set16(void *ptr, u16 val)
{
	u8 *bytes = ptr;
	for (u8 i = 0; i < sizeof(u16); i++)
	{
		bytes[i] = BYTE_LE(val, sizeof(u16) - 1 - i);
	}
}

static void set32(void *ptr, u32 val)
{
	u8 *bytes = ptr;
	for (u8 i = 0; i < sizeof(u32); i++)
	{
		bytes[i] = BYTE_LE(val, sizeof(u32) - 1 - i);
	}
}

static void set64(void *ptr, u64 val)
{
	u8 *bytes = ptr;
	for (u8 i = 0; i < sizeof(u64); i++)
	{
		bytes[i] = BYTE_LE(val, sizeof(u64) - 1 - i);
	}
}

int main()
{
	const u64 vaddr = (u64)0x400000;
	const u64 entry = (u64)0xb0;
	const u64 align = (u64)0x1000;

	exe_t exe;

	// 0x00
	set32(&exe.elf.imag, EI_MAG);
	exe.elf.iclass = EI_CLASS_64;
	exe.elf.idata = EI_DATA_LE;
	exe.elf.iversion = EI_VERSION;
	exe.elf.iosabi = EI_OSABI_SYSTEM_V;
	// 0x08
	exe.elf.iabiversion = EI_OSABI_ABIVERSION;
	exe.elf.ipad0 = 0x0;
	exe.elf.ipad1 = 0x0;
	exe.elf.ipad2 = 0x0;

	// 0x10
	exe.elf.type = ELF_TYPE_EXEC;
	exe.elf.mashine = ELF_MACHINE_AMD_X86_64;
	exe.elf.version = 1;
	// 0x18
	exe.elf.entry = vaddr + entry;

	// 0x20
	exe.elf.phoff = sizeof(exe.elf);
	// 0x28
	exe.elf.shoff = sizeof(exe.elf) + sizeof(exe.program) + sizeof(exe.data);

	// 0x30
	exe.elf.flags = ELF_FLAG_NONE;
	exe.elf.ehsize = sizeof(exe.elf);
	exe.elf.phentsize = sizeof(program_header_t);
	// 0x38
	exe.elf.phnum = sizeof(exe.program) / sizeof(program_header_t);
	exe.elf.shentsize = sizeof(section_header_t);
	exe.elf.shnum = sizeof(exe.section) / sizeof(section_header_t);
	exe.elf.shstrndx = 2;

	u8 code[] = {0x48, 0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05};

	// 0x40
	{
		exe.program[0].type = PH_TYPE_LOAD;
		exe.program[0].flags = PH_FLAG_R;
		exe.program[0].offset = 0;
		exe.program[0].vaddr = vaddr;
		exe.program[0].paddr = vaddr;
		exe.program[0].filesz = sizeof(exe.elf) + sizeof(exe.program);
		exe.program[0].memsz = sizeof(exe.elf) + sizeof(exe.program);
		exe.program[0].align = align;
	}

	// 0x78
	{
		exe.program[1].type = PH_TYPE_LOAD;
		exe.program[1].flags = PH_FLAG_X | PH_FLAG_R;
		exe.program[1].offset = entry;
		exe.program[1].vaddr = vaddr + entry;
		exe.program[1].paddr = vaddr + entry;
		exe.program[1].filesz = sizeof(code);
		exe.program[1].memsz = sizeof(code);
		exe.program[1].align = align;
	}

	char shstrtab[] = "\0.shstrtab";
	char text[] = "\0.text";

	memcpy(exe.code, code, sizeof(code));
	memcpy(&exe.strs[0], shstrtab, sizeof(shstrtab));
	memcpy(&exe.strs[sizeof(shstrtab) - 1], text, sizeof(text));

	// 0x1020 //.bss (Data section)
	{
		exe.section[0].name = 0;
		exe.section[0].type = SH_TYPE_UNKNOWN;
		exe.section[0].flags = SH_FLAG_NONE;
		exe.section[0].addr = 0;
		exe.section[0].offset = 0;
		exe.section[0].size = 0;
		exe.section[0].link = 0;
		exe.section[0].info = 0;
		exe.section[0].addralign = 0;
		exe.section[0].entsize = 0;
	}

	// 0x1060 //.text
	{
		exe.section[1].name = sizeof(shstrtab) - 1 + 1;
		exe.section[1].type = SH_TYPE_PROGBITS;
		exe.section[1].flags = SH_FLAG_ALLOC | SH_FLAG_EXECINSTR;
		exe.section[1].addr = vaddr + entry;
		exe.section[1].offset = entry;
		exe.section[1].size = sizeof(code);
		exe.section[1].link = 0;
		exe.section[1].info = 0;
		exe.section[1].addralign = 16;
		exe.section[1].entsize = 0;
	}

	// 0x10a0 //.shstrtab
	{
		exe.section[2].name = 1;
		exe.section[2].type = SH_TYPE_STRTAB;
		exe.section[2].flags = SH_FLAG_NONE;
		exe.section[2].addr = 0;
		exe.section[2].offset = entry + sizeof(code);
		exe.section[2].size = sizeof(exe.strs);
		exe.section[2].link = 0;
		exe.section[2].info = 0;
		exe.section[2].addralign = 1;
		exe.section[2].entsize = 0;
	}

	print_bytes(&exe, sizeof(exe));

	FILE *out = fopen("out", "wb");
	if (out == NULL)
	{
		printf("Failed to open file for writing\n");
		return 1;
	}

	fwrite(&exe, sizeof(exe), 1, out);

	fclose(out);

	return 0;
}
