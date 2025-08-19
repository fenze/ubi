/* ubi.c - universal binary interface
   Copyright (C) 2025 Kacper Fiedorowicz <fiedorowicz.kacper@gmail.com> */

#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifdef __linux__
# include <sys/sendfile.h>
#endif

struct elf_header
{
    unsigned char e_ident[16];  // ELF identification
    unsigned short e_type;      // Object file type
    unsigned short e_machine;   // Machine type
    unsigned int e_version;     // Object file version
    size_t e_entry;             // Entry point address
    size_t e_phoff;             // Program header offset
    size_t e_shoff;             // Section header offset
    unsigned int e_flags;       // Processor-specific flags
    unsigned short e_ehsize;    // ELF header size
    unsigned short e_phentsize; // Size of program header entry
    unsigned short e_phnum;     // Number of program headers
    unsigned short e_shentsize; // Size of section header entry
    unsigned short e_shnum;     // Number of section headers
    unsigned short e_shstrndx;  // Section name string table index
};

/* ELF machine types */
#define ELF_MACHINE_NONE         0x00
#define ELF_MACHINE_WE32100      0x01
#define ELF_MACHINE_SPARC        0x02
#define ELF_MACHINE_X86          0x03
#define ELF_MACHINE_M68K         0x04
#define ELF_MACHINE_M88K         0x05
#define ELF_MACHINE_INTEL_MCU    0x06
#define ELF_MACHINE_80860        0x07
#define ELF_MACHINE_MIPS         0x08
#define ELF_MACHINE_S370         0x09
#define ELF_MACHINE_MIPS_RS3_LE  0x0A
#define ELF_MACHINE_PARISC       0x0F
#define ELF_MACHINE_80960        0x13
#define ELF_MACHINE_PPC          0x14
#define ELF_MACHINE_PPC64        0x15
#define ELF_MACHINE_S390         0x16
#define ELF_MACHINE_SPU          0x17
#define ELF_MACHINE_V800         0x24
#define ELF_MACHINE_FR20         0x25
#define ELF_MACHINE_RH32         0x26
#define ELF_MACHINE_RCE          0x27
#define ELF_MACHINE_ARM          0x28
#define ELF_MACHINE_ALPHA        0x29
#define ELF_MACHINE_SH           0x2A
#define ELF_MACHINE_SPARCV9      0x2B
#define ELF_MACHINE_TRICORE      0x2C
#define ELF_MACHINE_ARC          0x2D
#define ELF_MACHINE_H8_300       0x2E
#define ELF_MACHINE_H8_300H      0x2F
#define ELF_MACHINE_H8S          0x30
#define ELF_MACHINE_H8_500       0x31
#define ELF_MACHINE_IA_64        0x32
#define ELF_MACHINE_MIPS_X       0x33
#define ELF_MACHINE_COLDFIRE     0x34
#define ELF_MACHINE_M68HC12      0x35
#define ELF_MACHINE_MMA          0x36
#define ELF_MACHINE_PCP          0x37
#define ELF_MACHINE_NCPU         0x38
#define ELF_MACHINE_NDR1         0x39
#define ELF_MACHINE_STARCORE     0x3A
#define ELF_MACHINE_ME16         0x3B
#define ELF_MACHINE_ST100        0x3C
#define ELF_MACHINE_TINYJ        0x3D
#define ELF_MACHINE_X86_64       0x3E
#define ELF_MACHINE_X86_64_ALIAS ELF_MACHINE_X86_64
#define ELF_MACHINE_AMD64        0x3E
#define ELF_MACHINE_SONY_DSP     0x3F
#define ELF_MACHINE_PDP10        0x40
#define ELF_MACHINE_PDP11        0x41
#define ELF_MACHINE_FX66         0x42
#define ELF_MACHINE_ST9PLUS      0x43
#define ELF_MACHINE_ST7          0x44
#define ELF_MACHINE_68HC16       0x45
#define ELF_MACHINE_68HC11       0x46
#define ELF_MACHINE_68HC08       0x47
#define ELF_MACHINE_68HC05       0x48
#define ELF_MACHINE_SVX          0x49
#define ELF_MACHINE_ST19         0x4A
#define ELF_MACHINE_VAX          0x4B
#define ELF_MACHINE_CRIS         0x4C
#define ELF_MACHINE_JAVELIN      0x4D
#define ELF_MACHINE_FIREPATH     0x4E
#define ELF_MACHINE_ZSP          0x4F
#define ELF_MACHINE_TMS320C6000  0x8C
#define ELF_MACHINE_E2K          0xAF
#define ELF_MACHINE_AARCH64      0xB7
#define ELF_MACHINE_Z80          0xDC
#define ELF_MACHINE_RISCV        0xF3
#define ELF_MACHINE_BPF          0xF7
#define ELF_MACHINE_WDC65C816    0x101
#define ELF_MACHINE_LOONGARCH    0x102

/* ELF file types */
#define ELF_FILETYPE_NONE   0x00   /* Unknown */
#define ELF_FILETYPE_REL    0x01   /* Relocatable file */
#define ELF_FILETYPE_EXEC   0x02   /* Executable file */
#define ELF_FILETYPE_DYN    0x03   /* Shared object */
#define ELF_FILETYPE_CORE   0x04   /* Core file */
#define ELF_FILETYPE_LOOS   0xFE00 /* Operating system specific (low) */
#define ELF_FILETYPE_HIOS   0xFEFF /* Operating system specific (high) */
#define ELF_FILETYPE_LOPROC 0xFF00 /* Processor specific (low) */
#define ELF_FILETYPE_HIPROC 0xFFFF /* Processor specific (high) */

struct macho_header
{
    unsigned int magic;      // Magic number
    unsigned int cputype;    // CPU type
    unsigned int cpusubtype; // CPU subtype
    unsigned int filetype;   // File type
    unsigned int ncmds;      // Number of load commands
    unsigned int sizeofcmds; // Size of load commands
    unsigned int flags;      // Flags
    unsigned int reserved;   // Reserved (64-bit only)
};

/* Mach-O CPU types */
#define MACHO_CPUTYPE_X86_64  0x01000007
#define MACHO_CPUTYPE_ARM64   0x0100000C
#define MACHO_CPUTYPE_X86     0x00000007
#define MACHO_CPUTYPE_ARM     0x0000000C
#define MACHO_CPUTYPE_VAX     0x00000001
#define MACHO_CPUTYPE_ROMP    0x00000002
#define MACHO_CPUTYPE_NS32032 0x00000004
#define MACHO_CPUTYPE_NS32332 0x00000005
#define MACHO_CPUTYPE_MC680x0 0x00000006
#define MACHO_CPUTYPE_MIPS    0x00000008
#define MACHO_CPUTYPE_NS32352 0x00000009
#define MACHO_CPUTYPE_HPPA    0x0000000B
#define MACHO_CPUTYPE_MC88000 0x0000000D
#define MACHO_CPUTYPE_SPARC   0x0000000E
#define MACHO_CPUTYPE_I860_BE 0x0000000F
#define MACHO_CPUTYPE_I860_LE 0x00000010
#define MACHO_CPUTYPE_RS6000  0x00000011
#define MACHO_CPUTYPE_POWERPC 0x00000012
#define MACHO_CPUTYPE_MC98000 0x00000012

/* x86 CPU subtypes for Mach-O */
#define MACHO_CPUSUBTYPE_X86_ALL            0x00000003 /* All x86 processors */
#define MACHO_CPUSUBTYPE_X86_486            0x00000004 /* Optimized for 486 or newer */
#define MACHO_CPUSUBTYPE_X86_486SX          0x00000084 /* Optimized for 486SX or newer */
#define MACHO_CPUSUBTYPE_X86_PENTIUM_M5     0x00000056 /* Optimized for Pentium M5 or newer */
#define MACHO_CPUSUBTYPE_X86_CELERON        0x00000067 /* Optimized for Celeron or newer */
#define MACHO_CPUSUBTYPE_X86_CELERON_MOBILE 0x00000077 /* Optimized for Celeron Mobile */
#define MACHO_CPUSUBTYPE_X86_PENTIUM_3      0x00000008 /* Optimized for Pentium 3 or newer */
#define MACHO_CPUSUBTYPE_X86_PENTIUM_3_M    0x00000018 /* Optimized for Pentium 3-M or newer */
#define MACHO_CPUSUBTYPE_X86_PENTIUM_3_XEON 0x00000028 /* Optimized for Pentium 3-XEON or newer */
#define MACHO_CPUSUBTYPE_X86_PENTIUM_4      0x0000000A /* Optimized for Pentium-4 or newer */
#define MACHO_CPUSUBTYPE_X86_ITANIUM        0x0000000B /* Optimized for Itanium or newer */
#define MACHO_CPUSUBTYPE_X86_ITANIUM_2      0x0000001B /* Optimized for Itanium-2 or newer */
#define MACHO_CPUSUBTYPE_X86_XEON           0x0000000C /* Optimized for XEON or newer */
#define MACHO_CPUSUBTYPE_X86_XEON_MP        0x0000001C /* Optimized for XEON-MP or newer */

/* ARM CPU subtypes for Mach-O */
#define MACHO_CPUSUBTYPE_ARM_ALL       0x00000000 /* All ARM processors */
#define MACHO_CPUSUBTYPE_ARM_A500_ARCH 0x00000001 /* Optimized for ARM-A500 ARCH or newer */
#define MACHO_CPUSUBTYPE_ARM_A500      0x00000002 /* Optimized for ARM-A500 or newer */
#define MACHO_CPUSUBTYPE_ARM_A440      0x00000003 /* Optimized for ARM-A440 or newer */
#define MACHO_CPUSUBTYPE_ARM_M4        0x00000004 /* Optimized for ARM-M4 or newer */
#define MACHO_CPUSUBTYPE_ARM_V4T       0x00000005 /* Optimized for ARM-V4T or newer */
#define MACHO_CPUSUBTYPE_ARM_V6        0x00000006 /* Optimized for ARM-V6 or newer */
#define MACHO_CPUSUBTYPE_ARM_V5TEJ     0x00000007 /* Optimized for ARM-V5TEJ or newer */
#define MACHO_CPUSUBTYPE_ARM_XSCALE    0x00000008 /* Optimized for ARM-XSCALE or newer */
#define MACHO_CPUSUBTYPE_ARM_V7        0x00000009 /* Optimized for ARM-V7 or newer */
#define MACHO_CPUSUBTYPE_ARM_V7F       0x0000000A /* Optimized for ARM-V7F (Cortex A9) or newer */
#define MACHO_CPUSUBTYPE_ARM_V7S       0x0000000B /* Optimized for ARM-V7S (Swift) or newer */
#define MACHO_CPUSUBTYPE_ARM_V7K       0x0000000C /* Optimized for ARM-V7K (Kirkwood40) or newer */
#define MACHO_CPUSUBTYPE_ARM_V8        0x0000000D /* Optimized for ARM-V8 or newer */
#define MACHO_CPUSUBTYPE_ARM_V6M       0x0000000E /* Optimized for ARM-V6M or newer */
#define MACHO_CPUSUBTYPE_ARM_V7M       0x0000000F /* Optimized for ARM-V7M or newer */
#define MACHO_CPUSUBTYPE_ARM_V7EM      0x00000010 /* Optimized for ARM-V7EM or newer */

/* Mach-O file types */
#define MACHO_FILETYPE_OBJECT      0x00000001 /* Relocatable object file */
#define MACHO_FILETYPE_EXECUTE     0x00000002 /* Demand paged executable file */
#define MACHO_FILETYPE_FVMLIB      0x00000003 /* Fixed VM shared library file */
#define MACHO_FILETYPE_CORE        0x00000004 /* Core file */
#define MACHO_FILETYPE_PRELOAD     0x00000005 /* Preloaded executable file */
#define MACHO_FILETYPE_DYLIB       0x00000006 /* Dynamically bound shared library file */
#define MACHO_FILETYPE_DYLINKER    0x00000007 /* Dynamic link editor */
#define MACHO_FILETYPE_BUNDLE      0x00000008 /* Dynamically bound bundle file */
#define MACHO_FILETYPE_DYLIB_STUB  0x00000009 /* Shared library stub for static linking only, no section contents */
#define MACHO_FILETYPE_DSYM        0x0000000A /* Companion file with only debug sections */
#define MACHO_FILETYPE_KEXT_BUNDLE 0x0000000B /* x86_64 kexts */
#define MACHO_FILETYPE_FILESET                                                                                         \
    0x0000000C /* A file composed of other Mach-Os to be run in the same userspace sharing a single linkedit */

enum
{
    /* Architectures */
    UBI_SECTION_X86 = 0x01,
    UBI_SECTION_X86_64 = 0x02,
    UBI_SECTION_AARCH64 = 0x03,              // Linux/ELF name for 64-bit ARM
    UBI_SECTION_ARM64 = UBI_SECTION_AARCH64, // Alias for macOS naming
    UBI_SECTION_ARM = 0x04,
    UBI_SECTION_PPC = 0x05,
    UBI_SECTION_PPC64 = 0x06,
    UBI_SECTION_MIPS = 0x07,
    UBI_SECTION_RISCV64 = 0x08,

    /* Binary formats */
    UBI_SECTION_ELF = 0x10,
    UBI_SECTION_MACHO = 0x20,
    UBI_SECTION_PE = 0x30,   // Windows Portable Executable
    UBI_SECTION_FAT = 0x40,  // Mach-O Fat Binary
    UBI_SECTION_OTHER = 0xF0 // Unknown/Other
};

#define UBI_MAX_SECTIONS 40

#define UBI_VERSION 1
#define UBI_MAGIC   0x55424900 // "UBI" in hex

#define UBI_PLATFORM_LINUX 0x01
#define UBI_PLATFORM_MACOS 0x02

struct ubi_header
{
    uint32_t magic;
    uint16_t version;
    uint16_t section_count;
    uint32_t section_flags[UBI_MAX_SECTIONS];
    uint64_t section_offsets[UBI_MAX_SECTIONS];
    uint64_t section_sizes[UBI_MAX_SECTIONS];
    uint64_t section_hashes[UBI_MAX_SECTIONS];
    uint64_t reserved[8];
};

/* Little-endian serialization helpers for ubi_header */

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
# define htole16(x) ((uint16_t) (x))
# define htole32(x) ((uint32_t) (x))
# define htole64(x) ((uint64_t) (x))
# define le16toh(x) ((uint16_t) (x))
# define le32toh(x) ((uint32_t) (x))
# define le64toh(x) ((uint64_t) (x))
#else
static inline uint16_t bswap16(uint16_t v)
{
    return (uint16_t) ((v >> 8) | (v << 8));
}
static inline uint32_t bswap32(uint32_t v)
{
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}
static inline uint64_t bswap64(uint64_t v)
{
    return ((uint64_t) bswap32((uint32_t) (v & 0xFFFFFFFFu)) << 32) | (uint64_t) bswap32((uint32_t) (v >> 32));
}
# define htole16(x) bswap16((uint16_t) (x))
# define htole32(x) bswap32((uint32_t) (x))
# define htole64(x) bswap64((uint64_t) (x))
# define le16toh(x) bswap16((uint16_t) (x))
# define le32toh(x) bswap32((uint32_t) (x))
# define le64toh(x) bswap64((uint64_t) (x))
#endif

static int ubi_header_write(FILE *f, const struct ubi_header *h)
{
    uint32_t magic = htole32((uint32_t) h->magic);
    uint16_t version = htole16((uint16_t) h->version);
    uint16_t section_count = htole16((uint16_t) h->section_count);

    if (fwrite(&magic, sizeof(magic), 1, f) != 1)
        return -1;
    if (fwrite(&version, sizeof(version), 1, f) != 1)
        return -1;
    if (fwrite(&section_count, sizeof(section_count), 1, f) != 1)
        return -1;

    for (size_t i = 0; i < UBI_MAX_SECTIONS; ++i) {
        uint32_t v = htole32((uint32_t) h->section_flags[i]);
        if (fwrite(&v, sizeof(v), 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; ++i) {
        uint64_t v = htole64((uint64_t) h->section_offsets[i]);
        if (fwrite(&v, sizeof(v), 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; ++i) {
        uint64_t v = htole64((uint64_t) h->section_sizes[i]);
        if (fwrite(&v, sizeof(v), 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; ++i) {
        uint64_t v = htole64((uint64_t) h->section_hashes[i]);
        if (fwrite(&v, sizeof(v), 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < 8; ++i) {
        uint64_t v = htole64((uint64_t) h->reserved[i]);
        if (fwrite(&v, sizeof(v), 1, f) != 1)
            return -1;
    }
    return 0;
}

static int ubi_header_read(FILE *f, struct ubi_header *h)
{
    uint32_t magic;
    uint16_t version, section_count;

    if (fread(&magic, sizeof(magic), 1, f) != 1)
        return -1;
    if (fread(&version, sizeof(version), 1, f) != 1)
        return -1;
    if (fread(&section_count, sizeof(section_count), 1, f) != 1)
        return -1;

    h->magic = le32toh(magic);
    h->version = le16toh(version);
    h->section_count = le16toh(section_count);

    for (size_t i = 0; i < UBI_MAX_SECTIONS; ++i) {
        uint32_t v;
        if (fread(&v, sizeof(v), 1, f) != 1)
            return -1;
        h->section_flags[i] = le32toh(v);
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; ++i) {
        uint64_t v;
        if (fread(&v, sizeof(v), 1, f) != 1)
            return -1;
        h->section_offsets[i] = le64toh(v);
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; ++i) {
        uint64_t v;
        if (fread(&v, sizeof(v), 1, f) != 1)
            return -1;
        h->section_sizes[i] = le64toh(v);
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; ++i) {
        uint64_t v;
        if (fread(&v, sizeof(v), 1, f) != 1)
            return -1;
        h->section_hashes[i] = le64toh(v);
    }
    for (size_t i = 0; i < 8; ++i) {
        uint64_t v;
        if (fread(&v, sizeof(v), 1, f) != 1)
            return -1;
        h->reserved[i] = le64toh(v);
    }
    return 0;
}

static size_t ubi_header_disk_size(void)
{
    return sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) * UBI_MAX_SECTIONS
         + sizeof(uint64_t) * UBI_MAX_SECTIONS /* offsets */
         + sizeof(uint64_t) * UBI_MAX_SECTIONS /* sizes */
         + sizeof(uint64_t) * UBI_MAX_SECTIONS /* hashes */
         + sizeof(uint64_t) * 8;
}

int todo(const char *msg)
{
    fprintf(stderr, "ubi: \033[33mtodo\033[m: %s\n", msg);
    return 1;
}

uint64_t ubi_fnv1a_hash(const void *data, size_t len)
{
    uint64_t hash = 14695981039346656037ULL;
    const unsigned char *p = (const unsigned char *) data;
    for (size_t i = 0; i < len; ++i) {
        hash ^= p[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

int error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    fputs("ubi: ", stderr);
    vfprintf(stderr, format, args);
    fputs("\n", stderr);
    va_end(args);
    return 1;
}

int execute(const char *path)
{
    int platform = 0;
    struct ubi_header header = {0};
    FILE *file = fopen(path, "rb");

    if (file == NULL)
        return error("failed to open file: %s", path);

    char shebang[32];
    long start_pos = ftell(file);
    if (fgets(shebang, sizeof(shebang), file) == NULL) {
        error("failed to read shebang from file: %s", path);
        fclose(file);
        return 1;
    }

    if (strncmp(shebang, "#!/usr/bin/env ubi", 18) != 0) {
        fseek(file, start_pos, SEEK_SET);
    }

    if (ubi_header_read(file, &header) != 0) {
        error("failed to read ubi header from file: %s", path);
        fclose(file);
        return 1;
    }

    if (header.magic != UBI_MAGIC) {
        error("invalid ubi binary format in file: %s (expected magic: 0x%zx, got: 0x%zx)", path, UBI_MAGIC,
              header.magic);
        fclose(file);
        return 1;
    }

    if (header.version != UBI_VERSION) {
        error("unsupported ubi version: %zu in file: %s", header.version, path);
        fclose(file);
        return 1;
    }

    struct utsname uname_info;
    if (uname(&uname_info) != 0) {
        error("failed to get system information");
        fclose(file);
        return 1;
    }

    if (strcmp(uname_info.sysname, "Linux") == 0) {
        platform = UBI_PLATFORM_LINUX;
    } else if (strcmp(uname_info.sysname, "Darwin") == 0) {
        platform = UBI_PLATFORM_MACOS;
    } else {
        error("ubi can only run on Linux or macOS");
        fclose(file);
        return 1;
    }

    size_t arch_flags = 0;
    if (strcmp(uname_info.machine, "x86_64") == 0)
        arch_flags = UBI_SECTION_X86_64;
    else if (strcmp(uname_info.machine, "x86") == 0)
        arch_flags = UBI_SECTION_X86;
    else if (strcmp(uname_info.machine, "aarch64") == 0 || strcmp(uname_info.machine, "arm64") == 0)
        arch_flags = UBI_SECTION_AARCH64;
    else if (strcmp(uname_info.machine, "armv7l") == 0 || strcmp(uname_info.machine, "armv8l") == 0)
        arch_flags = UBI_SECTION_ARM;
    else if (strcmp(uname_info.machine, "ppc64le") == 0)
        arch_flags = UBI_SECTION_PPC64;
    else if (strcmp(uname_info.machine, "ppc64") == 0)
        arch_flags = UBI_SECTION_PPC;
    else if (strcmp(uname_info.machine, "mips") == 0)
        arch_flags = UBI_SECTION_MIPS;
    else if (strcmp(uname_info.machine, "riscv64") == 0)
        arch_flags = UBI_SECTION_RISCV64;
    else {
        error("unsupported architecture: %s", uname_info.machine);
        fclose(file);
        return 1;
    }

    for (size_t i = 0; i < header.section_count; i++) {
        size_t flags = header.section_flags[i];
        size_t section_arch = flags & 0x0F;
        size_t section_format = flags & 0xF0;

        if (platform == UBI_PLATFORM_LINUX && section_format != UBI_SECTION_ELF
            && section_format != UBI_SECTION_MACHO) {
            continue;
        } else if (platform == UBI_PLATFORM_MACOS && section_format != UBI_SECTION_MACHO) {
            continue;
        }

        if (section_arch == arch_flags) {
            fseek(file, header.section_offsets[i], SEEK_SET);
            size_t section_size = header.section_sizes[i];
            fclose(file);

#ifdef __linux__
            char name[17];
            snprintf(name, sizeof(name), "%016llx", (unsigned long long) header.section_hashes[i]);
            int fd = memfd_create(name, MFD_CLOEXEC);
            if (fd == -1) {
                error("failed to create memfd: %s", name);
                return 1;
            }

            int in_fd = open(path, O_RDONLY);
            if (in_fd == -1) {
                error("failed to open ubi file for extraction: %s", path);
                close(fd);
                return 1;
            }

            off_t off = (off_t) header.section_offsets[i];
            size_t left = section_size;
            size_t written = 0;
            while (left > 0) {
                ssize_t s = sendfile(fd, in_fd, &off, left);
                if (s < 0) {
                    error("failed to copy section with sendfile: %s", name);
                    close(in_fd);
                    close(fd);
                    return 1;
                }
                if (s == 0) {
                    error("unexpected EOF when reading section data: %s", path);
                    close(in_fd);
                    close(fd);
                    return 1;
                }
                written += (size_t) s;
                left -= (size_t) s;
            }
            if (written != section_size) {
                error("section size mismatch: expected %zu, got %zu", section_size, written);
                close(in_fd);
                close(fd);
                return 1;
            }
            close(in_fd);
            fchmod(fd, 0755);
            char *args[] = {name, NULL};
            if (fexecve(fd, args, environ) == -1) {
                error("fexecve failed for section: %s", name);
                close(fd);
                return 1;
            }
            close(fd);
            return 1;
#elif __APPLE__
            mkdir("/tmp/ubi", 0777);
            char name[17];
            snprintf(name, sizeof(name), "%016llx", (unsigned long long) header.section_hashes[i]);
            char cache_path[128];
            snprintf(cache_path, sizeof(cache_path), "/tmp/ubi/%s", name);

            if (access(cache_path, X_OK) == 0) {
                execl(cache_path, cache_path, NULL);
                perror("execl failed");
                return 1;
            }

            // Use mmap for efficient extraction
            int ubi_fd = open(path, O_RDONLY);
            if (ubi_fd == -1) {
                error("failed to open ubi file for mmap: %s", path);
                return 1;
            }
            void *section_data = NULL;
            size_t page_size = sysconf(_SC_PAGESIZE);
            off_t map_offset = header.section_offsets[i] & ~(page_size - 1);
            off_t offset_in_map = header.section_offsets[i] - map_offset;
            size_t map_length = offset_in_map + section_size;
            section_data = mmap(NULL, map_length, PROT_READ, MAP_PRIVATE, ubi_fd, map_offset);
            if (section_data == MAP_FAILED) {
                error("mmap failed for section extraction.");
                close(ubi_fd);
                return 1;
            }

            int fd = open(cache_path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
            if (fd == -1) {
                error("failed to create cache file: %s", cache_path);
                munmap(section_data, map_length);
                close(ubi_fd);
                return 1;
            }
            size_t left = section_size;
            size_t written = 0;
            const char *src = (const char *) section_data + offset_in_map;
            while (left > 0) {
                ssize_t w = write(fd, src + written, left);
                if (w < 0) {
                    error("failed to write to cache file: %s", cache_path);
                    close(fd);
                    munmap(section_data, map_length);
                    close(ubi_fd);
                    return 1;
                }
                written += w;
                left -= w;
            }
            fchmod(fd, 0755);
            close(fd);
            munmap(section_data, map_length);
            close(ubi_fd);

            execl(cache_path, cache_path, NULL);
            perror("execl failed");
            return 1;
#endif
        }
    }

    error("no suitable section found for this platform/architecture in: %s", path);
    return 1;
}

int ubi_merge(char **source_files, int source_count, const char *output_file)
{
    struct ubi_header header = {0};

    FILE *output = fopen(output_file, "wb");
    if (output == NULL)
        return error("failed to open output file: %s", output_file);

    // Write shebang as the very first line
    const char *shebang = "#!/usr/bin/env ubi\n";
    size_t shebang_len = strlen(shebang);
    fwrite(shebang, 1, shebang_len, output);

    // Check section count limit
    if (source_count > UBI_MAX_SECTIONS) {
        error("too many sections: %d (max %d)", source_count, UBI_MAX_SECTIONS);
        fclose(output);
        return 1;
    }

    for (int i = 0; i < source_count; i++) {
        FILE *input = fopen(source_files[i], "rb");
        if (input == NULL) {
            error("failed to open source file: %s", source_files[i]);
            fclose(output);
            return 1;
        }

        unsigned char magic[4];
        fread(magic, 1, 4, input);

        size_t section_flags = 0;

        if (memcmp(magic,
                   "\x7f"
                   "ELF",
                   4)
            == 0) {
            section_flags |= UBI_SECTION_ELF;

            fseek(input, 0, SEEK_SET);
            struct elf_header elf_hdr;
            fread(&elf_hdr, 1, sizeof(elf_hdr), input);

            // Architecture
            switch (elf_hdr.e_machine) {
            case ELF_MACHINE_X86:
                section_flags |= UBI_SECTION_X86;
                break;
            case ELF_MACHINE_X86_64:
                section_flags |= UBI_SECTION_X86_64;
                break;
            case ELF_MACHINE_AARCH64:
                section_flags |= UBI_SECTION_AARCH64;
                break;
            case ELF_MACHINE_ARM:
                section_flags |= UBI_SECTION_ARM;
                break;
            case ELF_MACHINE_PPC:
                section_flags |= UBI_SECTION_PPC;
                break;
            case ELF_MACHINE_PPC64:
                section_flags |= UBI_SECTION_PPC64;
                break;
            case ELF_MACHINE_MIPS:
                section_flags |= UBI_SECTION_MIPS;
                break;
            case ELF_MACHINE_RISCV:
                section_flags |= UBI_SECTION_RISCV64;
                break;
            default:
                error("unsupported elf machine type: %u", elf_hdr.e_machine);
                fclose(input);
                fclose(output);
                return 1;
            }

            // Check for static linking: ELF is static if there is no PT_INTERP program header
            // Read program headers to look for PT_INTERP (type 3)
            int is_static = 1; // Assume static unless PT_INTERP is found
            if (elf_hdr.e_phoff && elf_hdr.e_phnum > 0) {
                // Seek to the start of the program header table
                fseek(input, elf_hdr.e_phoff, SEEK_SET);
                for (int ph = 0; ph < elf_hdr.e_phnum; ++ph) {
                    unsigned char phdr[56]; // Enough for both 32/64-bit program headers
                    size_t phdr_size = elf_hdr.e_phentsize;
                    if (phdr_size > sizeof(phdr))
                        phdr_size = sizeof(phdr);
                    // Read one program header entry
                    fread(phdr, 1, phdr_size, input);
                    // The first 4 bytes are p_type (program header type)
                    // PT_INTERP is 3. This is true for both little and big endian ELF.
                    // We read as little-endian here, which is fine for most platforms.
                    unsigned int p_type = phdr[0] | (phdr[1] << 8) | (phdr[2] << 16) | (phdr[3] << 24);
                    if (p_type == 3) { // PT_INTERP found: this means dynamically linked
                        is_static = 0;
                        break;
                    }
                }
            }

            if (!(elf_hdr.e_type == ELF_FILETYPE_EXEC || elf_hdr.e_type == ELF_FILETYPE_DYN)) {
                error("ELF file is not executable: %s (e_type=%u)", source_files[i], elf_hdr.e_type);
                fclose(input);
                fclose(output);
                return 1;
            }
            if (!is_static) {
                error("ELF file is not statically linked: %s", source_files[i]);
                fclose(input);
                fclose(output);
                return 1;
            }
        } else if (memcmp(magic, "\xCE\xFA\xED\xFE", 4) == 0 || // 32-bit Mach-O
                   memcmp(magic, "\xCF\xFA\xED\xFE", 4) == 0    // 64-bit Mach-O
        ) {
            section_flags |= UBI_SECTION_MACHO;

            // Read Mach-O header as raw bytes to handle endianness
            unsigned char macho_hdr_buf[sizeof(struct macho_header)];
            if (fseek(input, 0, SEEK_SET) != 0) {
                perror("ubi: fseek failed for Mach-O input");
                fclose(input);
                fclose(output);
                return 1;
            }

            if (fread(macho_hdr_buf, 1, sizeof(macho_hdr_buf), input) != sizeof(macho_hdr_buf)) {
                perror("ubi: fread failed for Mach-O header");
                fclose(input);
                fclose(output);
                return 1;
            }

            // Detect endianness from magic number
            // Mach-O magic numbers:
            //   0xCEFAEDFE (32-bit little-endian)
            //   0xCFFAEDFE (64-bit little-endian)
            //   0xFEEDFACE (32-bit big-endian)
            //   0xFEEDFACF (64-bit big-endian)
            // We only check for little-endian here (0xCE or 0xCF as first byte)
            int is_le = (magic[0] == 0xCE || magic[0] == 0xCF); // little-endian

            unsigned int cputype, filetype;
            if (is_le) {
                // For little-endian, fields are stored in reverse byte order
                // cputype is at offset 4..7, filetype at offset 12..15
                cputype =
                    (macho_hdr_buf[7] << 24) | (macho_hdr_buf[6] << 16) | (macho_hdr_buf[5] << 8) | macho_hdr_buf[4];
                filetype = (macho_hdr_buf[15] << 24) | (macho_hdr_buf[14] << 16) | (macho_hdr_buf[13] << 8)
                         | macho_hdr_buf[12];
            } else {
                // For big-endian, fields are stored in natural order
                // cputype is at offset 4..7, filetype at offset 12..15
                cputype =
                    (macho_hdr_buf[4] << 24) | (macho_hdr_buf[5] << 16) | (macho_hdr_buf[6] << 8) | macho_hdr_buf[7];
                filetype = (macho_hdr_buf[12] << 24) | (macho_hdr_buf[13] << 16) | (macho_hdr_buf[14] << 8)
                         | macho_hdr_buf[15];
            }

            // Architecture
            switch (cputype) {
            case MACHO_CPUTYPE_X86:
                section_flags |= UBI_SECTION_X86;
                break;
            case MACHO_CPUTYPE_X86_64:
                section_flags |= UBI_SECTION_X86_64;
                break;
            case MACHO_CPUTYPE_ARM64:
                section_flags |= UBI_SECTION_ARM64;
                break;
            case MACHO_CPUTYPE_ARM:
                section_flags |= UBI_SECTION_ARM;
                break;
            case MACHO_CPUTYPE_POWERPC:
                section_flags |= UBI_SECTION_PPC;
                break;
            case MACHO_CPUTYPE_MIPS:
                section_flags |= UBI_SECTION_MIPS;
                break;
            default:
                error("unsupported mach-o cpu type: %u", cputype);
                fclose(input);
                fclose(output);
                return 1;
            }

            if (filetype != MACHO_FILETYPE_EXECUTE) {
                error("Mach-O file is not executable: %s (filetype=%u)", source_files[i], filetype);
                fclose(input);
                fclose(output);
                return 1;
            }
        } else {
            error("unknown file format: %s (%02x%02x%02x%02x)", source_files[i], magic[0], magic[1], magic[2],
                  magic[3]);
            fclose(input);
            fclose(output);
            return 1;
        }

        // Get section size for later
        fseek(input, 0, SEEK_END);
        size_t file_size = ftell(input);
        fseek(input, 0, SEEK_SET);

        header.section_flags[i] = section_flags;
        header.section_sizes[i] = file_size;

        char *buffer = malloc(file_size);
        if (buffer == NULL) {
            error("memory allocation failed for buffer.");
            fclose(input);
            fclose(output);
            return 1;
        }
        fread(buffer, 1, file_size, input);
        header.section_hashes[i] = ubi_fnv1a_hash(buffer, file_size);
        free(buffer);

        fclose(input);
    }

    header.magic = UBI_MAGIC;
    header.version = UBI_VERSION;
    header.section_count = source_count;

    fseek(output, (long) shebang_len, SEEK_SET);
    if (ubi_header_write(output, &header) != 0) {
        error("failed to write ubi header to output file: %s", output_file);
        fclose(output);
        return 1;
    }

    // Move file pointer to immediately after header for section writing
    fseek(output, (long) shebang_len + (long) ubi_header_disk_size(), SEEK_SET);

    // Write all sections sequentially, updating offsets
    for (int i = 0; i < source_count; i++) {
        FILE *input = fopen(source_files[i], "rb");
        if (input == NULL) {
            error("failed to reopen source file: %s", source_files[i]);
            fclose(output);
            return 1;
        }

        header.section_offsets[i] = ftell(output);

        char *buffer = malloc(header.section_sizes[i]);
        if (buffer == NULL) {
            error("memory allocation failed for buffer.");
            fclose(input);
            fclose(output);
            return 1;
        }

        fread(buffer, 1, header.section_sizes[i], input);
        fwrite(buffer, 1, header.section_sizes[i], output);

        free(buffer);
        fclose(input);
    }

    if (fseek(output, (long) shebang_len, SEEK_SET) != 0) {
        perror("ubi: fseek failed when writing header");
        fclose(output);
        return 1;
    }
    if (ubi_header_write(output, &header) != 0) {
        error("failed to write ubi header to output file: %s", output_file);
        fclose(output);
        return 1;
    }

    if (chmod(output_file, 0755) != 0) {
        error("failed to set executable permissions on output file: %s", output_file);
        fclose(output);
        return 1;
    }

    if (fclose(output) != 0) {
        perror("ubi: fclose failed on output file");
        return 1;
    }
    free(source_files);

    return 0;
}

int ubi_inspect(const char *binary_path)
{
    FILE *file = fopen(binary_path, "rb");
    if (file == NULL) {
        error("failed to open binary file: %s", binary_path);
        return 1;
    }

    char shebang[20];
    if (fgets(shebang, sizeof(shebang), file) == NULL || strncmp(shebang, "#!/usr/bin/env ubi", 18) != 0) {
        // Not a shebang, rewind to start
        if (fseek(file, 0, SEEK_SET) != 0) {
            perror("ubi: fseek failed");
            fclose(file);
            return 1;
        }
    }

    struct ubi_header hdr;
    if (ubi_header_read(file, &hdr) != 0) {
        fclose(file);
        return error("failed to read ubi header.");
    }
    fclose(file);

    if (hdr.magic != 0x55424900) {
        error("invalid ubi binary format.");
        return 1;
    }

    printf("UBI Binary Header:\n");
    printf("  Magic: 0x%08x\n", (unsigned) hdr.magic);
    printf("  Version: %u\n", (unsigned) hdr.version);
    printf("  Section Count: %u\n", (unsigned) hdr.section_count);

    for (size_t i = 0; i < hdr.section_count; i++) {
        printf("  Section %zu:\n", i);
        printf("    Flags: 0x%08x\n", (unsigned) hdr.section_flags[i]);
        size_t format = hdr.section_flags[i] & 0xF0;
        size_t arch = hdr.section_flags[i] & 0x0F;

        switch (format) {
        case UBI_SECTION_ELF:
            printf("      ELF\n");
            break;
        case UBI_SECTION_MACHO:
            printf("      Mach-O\n");
            break;
        case UBI_SECTION_PE:
            printf("      PE\n");
            break;
        case UBI_SECTION_FAT:
            printf("      Fat\n");
            break;
        case UBI_SECTION_OTHER:
            printf("      Other\n");
            break;
        default:
            printf("      Unknown format\n");
            break;
        }
        switch (arch) {
        case UBI_SECTION_X86:
            printf("      x86\n");
            break;
        case UBI_SECTION_X86_64:
            printf("      x86_64\n");
            break;
        case UBI_SECTION_AARCH64:
            printf("      aarch64/arm64\n");
            break;
        case UBI_SECTION_ARM:
            printf("      arm\n");
            break;
        case UBI_SECTION_PPC:
            printf("      ppc\n");
            break;
        case UBI_SECTION_PPC64:
            printf("      ppc64\n");
            break;
        case UBI_SECTION_MIPS:
            printf("      mips\n");
            break;
        case UBI_SECTION_RISCV64:
            printf("      riscv64\n");
            break;
        default:
            printf("      Unknown arch\n");
            break;
        }
        printf("    Offset: %llu\n", (unsigned long long) hdr.section_offsets[i]);
        printf("    Size: %llu", (unsigned long long) hdr.section_sizes[i]);
        if (hdr.section_sizes[i] >= 1024 * 1024) {
            printf(" (%.2f MB)", (double) hdr.section_sizes[i] / (1024.0 * 1024.0));
        } else if (hdr.section_sizes[i] >= 1024) {
            printf(" (%.2f kB)", (double) hdr.section_sizes[i] / 1024.0);
        }
        printf("\n");
    }

    return 0;
}

int help(const char *progname)
{
    fprintf(stderr, "usage: %s [options] [executable...]\n", progname);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  inspect <binary>    Inspect a UBI binary file.\n");
    fprintf(stderr, "  -o <output>         Specify output file name.\n");
    fprintf(stderr, "  --version           Show version information.\n");
    fprintf(stderr, "  --help              Show this help message.\n");
    return 0;
}

int main(int argc, char **argv)
{
    int source_count = 0;
    char **source_files = NULL;
    const char *output_file = "a.out";

    if (argc == 1)
        return help(argv[0]);

    if (argc == 2 && argv[1][0] != '-')
        return execute(argv[1]);

    if (strcmp(argv[1], "inspect") == 0) {
        if (argc < 3) {
            error("no binary specified for inspection.");
            return 1;
        }

        return ubi_inspect(argv[2]);
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-o") == 0) {
                if (output_file != NULL) {
                    error("output file already specified with -o option.");
                    return 1;
                }

                if (i + 1 < argc) {
                    output_file = argv[++i];
                } else {
                    error("no output file specified after -o option.");
                    return 1;
                }
            } else if (argv[i][1] == '-') {
                if (strcmp(argv[i], "--help") == 0) {
                    help(argv[0]);
                } else if (strcmp(argv[i], "--version") == 0) {
                    printf("ubi version 1.0\n");
                    return 0;
                } else {
                    error("unknown option - `%s`", argv[i]);
                    return 1;
                }
            }
        } else {
            source_files = realloc(source_files, sizeof(char *) * (source_count + 1));
            if (source_files == NULL) {
                error("memory allocation failed for source files.");
                return 1;
            }

            source_files[source_count++] = argv[i];
        }
    }

    if (source_count == 0)
        return error("no source files specified.");

    return ubi_merge(source_files, source_count, output_file);
}
