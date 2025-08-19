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
    unsigned char e_ident[16];
    unsigned short e_type;
    unsigned short e_machine;
    unsigned int e_version;
    size_t e_entry;
    size_t e_phoff;
    size_t e_shoff;
    unsigned int e_flags;
    unsigned short e_ehsize;
    unsigned short e_phentsize;
    unsigned short e_phnum;
    unsigned short e_shentsize;
    unsigned short e_shnum;
    unsigned short e_shstrndx;
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

#define ELF_FILETYPE_NONE   0x00
#define ELF_FILETYPE_REL    0x01
#define ELF_FILETYPE_EXEC   0x02
#define ELF_FILETYPE_DYN    0x03
#define ELF_FILETYPE_CORE   0x04
#define ELF_FILETYPE_LOOS   0xFE00
#define ELF_FILETYPE_HIOS   0xFEFF
#define ELF_FILETYPE_LOPROC 0xFF00
#define ELF_FILETYPE_HIPROC 0xFFFF

struct macho_header
{
    unsigned int magic;
    unsigned int cputype;
    unsigned int cpusubtype;
    unsigned int filetype;
    unsigned int ncmds;
    unsigned int sizeofcmds;
    unsigned int flags;
    unsigned int reserved;
};

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

#define MACHO_FILETYPE_OBJECT      0x00000001
#define MACHO_FILETYPE_EXECUTE     0x00000002
#define MACHO_FILETYPE_FVMLIB      0x00000003
#define MACHO_FILETYPE_CORE        0x00000004
#define MACHO_FILETYPE_PRELOAD     0x00000005
#define MACHO_FILETYPE_DYLIB       0x00000006
#define MACHO_FILETYPE_DYLINKER    0x00000007
#define MACHO_FILETYPE_BUNDLE      0x00000008
#define MACHO_FILETYPE_DYLIB_STUB  0x00000009
#define MACHO_FILETYPE_DSYM        0x0000000A
#define MACHO_FILETYPE_KEXT_BUNDLE 0x0000000B
#define MACHO_FILETYPE_FILESET     0x0000000C

enum
{
    UBI_SECTION_X86 = 0x01,
    UBI_SECTION_X86_64 = 0x02,
    UBI_SECTION_AARCH64 = 0x03,
    UBI_SECTION_ARM64 = UBI_SECTION_AARCH64,
    UBI_SECTION_ARM = 0x04,
    UBI_SECTION_PPC = 0x05,
    UBI_SECTION_PPC64 = 0x06,
    UBI_SECTION_MIPS = 0x07,
    UBI_SECTION_RISCV64 = 0x08,
    UBI_SECTION_S390X = 0x09,
    UBI_SECTION_LOONGARCH64 = 0x0A,
    UBI_SECTION_SPARC64 = 0x0B,
    UBI_SECTION_M68K = 0x0C,

    UBI_SECTION_ELF = 0x10,
    UBI_SECTION_MACHO = 0x20,
    UBI_SECTION_PE = 0x30,
    UBI_SECTION_FAT = 0x40,
    UBI_SECTION_OTHER = 0xF0
};

#define UBI_MAX_SECTIONS   40
#define UBI_VERSION        1
#define UBI_MAGIC          0x55424900
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

/* Endian helpers */
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

/* Header serialization */
static int ubi_header_write(FILE *f, const struct ubi_header *h)
{
    uint32_t magic = htole32(h->magic);
    uint16_t version = htole16(h->version);
    uint16_t section_count = htole16(h->section_count);
    if (fwrite(&magic, sizeof magic, 1, f) != 1)
        return -1;
    if (fwrite(&version, sizeof version, 1, f) != 1)
        return -1;
    if (fwrite(&section_count, sizeof section_count, 1, f) != 1)
        return -1;
    for (size_t i = 0; i < UBI_MAX_SECTIONS; i++) {
        uint32_t v = htole32(h->section_flags[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; i++) {
        uint64_t v = htole64(h->section_offsets[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; i++) {
        uint64_t v = htole64(h->section_sizes[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; i++) {
        uint64_t v = htole64(h->section_hashes[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < 8; i++) {
        uint64_t v = htole64(h->reserved[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }
    return 0;
}

static int ubi_header_read(FILE *f, struct ubi_header *h)
{
    uint32_t magic;
    uint16_t version, section_count;

    if (fread(&magic, sizeof magic, 1, f) != 1)
        return -1;

    if (fread(&version, sizeof version, 1, f) != 1)
        return -1;

    if (fread(&section_count, sizeof section_count, 1, f) != 1)
        return -1;

    h->magic = le32toh(magic);
    h->version = le16toh(version);
    h->section_count = le16toh(section_count);
    if (h->section_count > UBI_MAX_SECTIONS)
        return -1;
    for (size_t i = 0; i < UBI_MAX_SECTIONS; i++) {
        uint32_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->section_flags[i] = le32toh(v);
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; i++) {
        uint64_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->section_offsets[i] = le64toh(v);
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; i++) {
        uint64_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->section_sizes[i] = le64toh(v);
    }
    for (size_t i = 0; i < UBI_MAX_SECTIONS; i++) {
        uint64_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->section_hashes[i] = le64toh(v);
    }
    for (size_t i = 0; i < 8; i++) {
        uint64_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->reserved[i] = le64toh(v);
    }
    return 0;
}

static size_t ubi_header_disk_size(void)
{
    return sizeof(uint32_t) + 2 * sizeof(uint16_t) + sizeof(uint32_t) * UBI_MAX_SECTIONS
         + sizeof(uint64_t) * UBI_MAX_SECTIONS * 3 + sizeof(uint64_t) * 8;
}

uint64_t ubi_fnv1a_hash(const void *data, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    const unsigned char *p = (const unsigned char *) data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

int error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("ubi: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    return 1;
}

int execute(const char *path)
{
    struct ubi_header header = {0};
    FILE *f = fopen(path, "rb");
    if (!f)
        return error("failed to open file: %s", path);

    /* Handle optional shebang */
    long start = ftell(f);
    char shebang[32];
    if (fgets(shebang, sizeof shebang, f) == NULL) {
        fclose(f);
        return error("failed to read file: %s", path);
    }
    if (strncmp(shebang, "#!/usr/bin/env ubi", 18) != 0)
        fseek(f, start, SEEK_SET);

    if (ubi_header_read(f, &header) != 0) {
        fclose(f);
        return error("failed to read ubi header from file: %s", path);
    }
    if (header.magic != UBI_MAGIC) {
        fclose(f);
        return error("invalid ubi magic in file: %s", path);
    }
    if (header.version != UBI_VERSION) {
        fclose(f);
        return error("unsupported ubi version (%u) in file: %s", (unsigned) header.version, path);
    }
    if (header.section_count > UBI_MAX_SECTIONS) {
        fclose(f);
        return error("invalid section count %u", (unsigned) header.section_count);
    }
    long after_hdr = ftell(f);
    if (after_hdr < 0) {
        fclose(f);
        return error("ftell failed");
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return error("seek end failed");
    }
    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return error("ftell end failed");
    }
    if (fseek(f, after_hdr, SEEK_SET) != 0) {
        fclose(f);
        return error("seek restore failed");
    }

    int pe_present = 0;
    for (size_t i = 0; i < header.section_count; i++) {
        uint64_t off = header.section_offsets[i];
        uint64_t sz = header.section_sizes[i];
        if (sz == 0 || off + sz > (uint64_t) file_size) {
            fclose(f);
            return error("section %zu out of bounds", i);
        }
    }

    /* Platform / arch detect */
    int platform = 0;
    struct utsname u;
    if (uname(&u) != 0) {
        fclose(f);
        return error("uname failed");
    }
    if (strcmp(u.sysname, "Linux") == 0)
        platform = UBI_PLATFORM_LINUX;
    else if (strcmp(u.sysname, "Darwin") == 0)
        platform = UBI_PLATFORM_MACOS;
    else {
        fclose(f);
        return error("unsupported platform %s", u.sysname);
    }

    size_t want_arch = 0;
    if (!strcmp(u.machine, "x86_64"))
        want_arch = UBI_SECTION_X86_64;
    else if (!strcmp(u.machine, "x86") || !strcmp(u.machine, "i386"))
        want_arch = UBI_SECTION_X86;
    else if (!strcmp(u.machine, "aarch64") || !strcmp(u.machine, "arm64"))
        want_arch = UBI_SECTION_AARCH64;
    else if (!strcmp(u.machine, "armv7l") || !strcmp(u.machine, "armv7") || !strcmp(u.machine, "armv8l"))
        want_arch = UBI_SECTION_ARM;
    else if (!strcmp(u.machine, "ppc64") || !strcmp(u.machine, "ppc64le"))
        want_arch = UBI_SECTION_PPC64;
    else if (!strcmp(u.machine, "ppc"))
        want_arch = UBI_SECTION_PPC;
    else if (!strcmp(u.machine, "mips"))
        want_arch = UBI_SECTION_MIPS;
    else if (!strcmp(u.machine, "riscv64"))
        want_arch = UBI_SECTION_RISCV64;
    else if (!strcmp(u.machine, "s390x"))
        want_arch = UBI_SECTION_S390X;
    else if (!strcmp(u.machine, "loongarch64"))
        want_arch = UBI_SECTION_LOONGARCH64;
    else if (!strcmp(u.machine, "sparc64"))
        want_arch = UBI_SECTION_SPARC64;
    else if (!strcmp(u.machine, "m68k"))
        want_arch = UBI_SECTION_M68K;
    else {
        fclose(f);
        return error("unsupported architecture: %s", u.machine);
    }

    for (size_t i = 0; i < header.section_count; i++) {
        uint32_t flags = header.section_flags[i];
        uint32_t fmt = flags & 0xF0;
        uint32_t arch = flags & 0x0F;

        if (fmt == UBI_SECTION_PE) { /* PE only supported on Windows (not implemented yet) */
            pe_present = 1;
            continue;
        }

        if (arch != want_arch)
            continue;
        if (platform == UBI_PLATFORM_LINUX) {
            if (!(fmt == UBI_SECTION_ELF || fmt == UBI_SECTION_MACHO))
                continue;
        } else if (platform == UBI_PLATFORM_MACOS) {
            if (fmt != UBI_SECTION_MACHO)
                continue;
        }

        /* Extract and execute */
        uint64_t off = header.section_offsets[i];
        uint64_t sz = header.section_sizes[i];
        if (fseek(f, (long) off, SEEK_SET) != 0) {
            fclose(f);
            return error("seek to section failed");
        }

#ifdef __linux__
        char name[17];
        snprintf(name, sizeof name, "%016llx", (unsigned long long) header.section_hashes[i]);
        int memfd = memfd_create(name, MFD_CLOEXEC);
        if (memfd == -1) {
            fclose(f);
            return error("memfd_create failed");
        }
        int infile = open(path, O_RDONLY);
        if (infile == -1) {
            close(memfd);
            fclose(f);
            return error("open ubi file failed");
        }
        off_t cur_off = (off_t) off;
        uint64_t left = sz;
        while (left > 0) {
            ssize_t s = sendfile(memfd, infile, &cur_off, left);
            if (s <= 0) {
                close(infile);
                close(memfd);
                fclose(f);
                return error("sendfile failed");
            }
            left -= (uint64_t) s;
        }
        close(infile);
        fchmod(memfd, 0755);
        char *args[] = {name, NULL};
        extern char **environ;
        fexecve(memfd, args, environ);
        close(memfd);
        fclose(f);
        return error("fexecve failed");
#elif __APPLE__
        mkdir("/tmp/ubi", 0777);
        char hashname[17];
        snprintf(hashname, sizeof hashname, "%016llx", (unsigned long long) header.section_hashes[i]);
        char cpath[128];
        snprintf(cpath, sizeof cpath, "/tmp/ubi/%s", hashname);
        if (access(cpath, X_OK) == 0) {
            execl(cpath, cpath, NULL);
            fclose(f);
            return error("execl failed");
        }
        int out = open(cpath, O_CREAT | O_WRONLY | O_TRUNC, 0755);
        if (out == -1) {
            fclose(f);
            return error("open cache failed");
        }
        const size_t chunk = 1 << 20;
        uint64_t remaining = sz;
        if (fseek(f, (long) off, SEEK_SET) != 0) {
            close(out);
            fclose(f);
            return error("seek failed");
        }
        char *buf = malloc(chunk);
        if (!buf) {
            close(out);
            fclose(f);
            return error("malloc failed");
        }
        while (remaining > 0) {
            size_t rd = remaining > chunk ? chunk : (size_t) remaining;
            if (fread(buf, 1, rd, f) != rd) {
                free(buf);
                close(out);
                fclose(f);
                return error("short read section");
            }
            if (write(out, buf, rd) != (ssize_t) rd) {
                free(buf);
                close(out);
                fclose(f);
                return error("short write section");
            }
            remaining -= rd;
        }
        free(buf);
        close(out);
        execl(cpath, cpath, NULL);
        fclose(f);
        return error("execl failed");
#endif
    }

    fclose(f);
    if (pe_present)
        return error("found matching PE section but Windows platform support is not implemented");

    return error("no suitable section found in %s", path);
}

int ubi_merge(char **sources, int count, const char *out_path)
{
    if (count > UBI_MAX_SECTIONS)
        return error("too many sections: %d (max %d)", count, UBI_MAX_SECTIONS);

    FILE *out = fopen(out_path, "wb");
    if (!out)
        return error("failed to open output file: %s", out_path);

    const char *shebang = "#!/usr/bin/env ubi\n";
    size_t shebang_len = strlen(shebang);
    if (fwrite(shebang, 1, shebang_len, out) != shebang_len) {
        fclose(out);
        return error("failed to write shebang");
    }

    struct ubi_header hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.magic = UBI_MAGIC;
    hdr.version = UBI_VERSION;
    hdr.section_count = (uint16_t) count;

    /* Reserve header space */
    if (fseek(out, (long) (shebang_len + ubi_header_disk_size()), SEEK_SET) != 0) {
        fclose(out);
        return error("failed to reserve header space");
    }

    for (int i = 0; i < count; i++) {
        FILE *in = fopen(sources[i], "rb");
        if (!in) {
            fclose(out);
            return error("failed to open source: %s", sources[i]);
        }

        unsigned char magic[4];
        if (fread(magic, 1, 4, in) != 4) {
            fclose(in);
            fclose(out);
            return error("failed to read magic: %s", sources[i]);
        }
        size_t flags = 0;

        /* --- ELF detection and parsing --- */
        if (memcmp(magic,
                   "\x7F"
                   "ELF",
                   4)
            == 0) {
            flags |= UBI_SECTION_ELF;
            /* Robust ELF header read (first 64 bytes cover both 32/64) */
            unsigned char ehdr[64];
            if (fseek(in, 0, SEEK_SET) != 0 || fread(ehdr, 1, 64, in) != 64) {
                fclose(in);
                fclose(out);
                return error("failed to read ELF header: %s", sources[i]);
            }
            int is_64 = (ehdr[4] == 2);
            uint16_t e_type = (uint16_t) (ehdr[16] | (ehdr[17] << 8));
            uint16_t e_machine = (uint16_t) (ehdr[18] | (ehdr[19] << 8));
            uint64_t e_phoff = 0;
            uint16_t e_phentsize = 0;
            uint16_t e_phnum = 0;
            if (!is_64) {
                e_phoff = (uint32_t) (ehdr[28] | (ehdr[29] << 8) | (ehdr[30] << 16) | (ehdr[31] << 24));
                e_phentsize = (uint16_t) (ehdr[42] | (ehdr[43] << 8));
                e_phnum = (uint16_t) (ehdr[44] | (ehdr[45] << 8));
            } else {
                e_phoff = ((uint64_t) ehdr[32]) | ((uint64_t) ehdr[33] << 8) | ((uint64_t) ehdr[34] << 16)
                        | ((uint64_t) ehdr[35] << 24) | ((uint64_t) ehdr[36] << 32) | ((uint64_t) ehdr[37] << 40)
                        | ((uint64_t) ehdr[38] << 48) | ((uint64_t) ehdr[39] << 56);
                e_phentsize = (uint16_t) (ehdr[54] | (ehdr[55] << 8));
                e_phnum = (uint16_t) (ehdr[56] | (ehdr[57] << 8));
            }

            int archmap[] = {
                [ELF_MACHINE_X86] = UBI_SECTION_X86,         [ELF_MACHINE_X86_64] = UBI_SECTION_X86_64,
                [ELF_MACHINE_AARCH64] = UBI_SECTION_AARCH64, [ELF_MACHINE_ARM] = UBI_SECTION_ARM,
                [ELF_MACHINE_PPC] = UBI_SECTION_PPC,         [ELF_MACHINE_PPC64] = UBI_SECTION_PPC64,
                [ELF_MACHINE_MIPS] = UBI_SECTION_MIPS,       [ELF_MACHINE_RISCV] = UBI_SECTION_RISCV64,
                [ELF_MACHINE_S390] = UBI_SECTION_S390X,      [ELF_MACHINE_LOONGARCH] = UBI_SECTION_LOONGARCH64,
                [ELF_MACHINE_SPARCV9] = UBI_SECTION_SPARC64, [ELF_MACHINE_M68K] = UBI_SECTION_M68K};

            int arch = 0;
            if (e_machine < (int) (sizeof(archmap) / sizeof(archmap[0])))
                arch = archmap[e_machine];

            if (!arch) {
                fclose(in);
                fclose(out);
                return error("unsupported elf machine: %u", e_machine);
            }
            flags |= arch;

            if (!(e_type == ELF_FILETYPE_EXEC || e_type == ELF_FILETYPE_DYN)) {
                fclose(in);
                fclose(out);
                return error("ELF not executable: %s", sources[i]);
            }

            /* Static detection: absence of PT_INTERP (type 3) */
            int is_static = 1;
            if (e_phoff && e_phnum && e_phentsize >= 4) {
                for (uint16_t ph = 0; ph < e_phnum; ph++) {
                    uint64_t off = e_phoff + (uint64_t) ph * e_phentsize;
                    if (fseek(in, (long) off, SEEK_SET) != 0) {
                        fclose(in);
                        fclose(out);
                        return error("seek phdr failed: %s", sources[i]);
                    }
                    unsigned char p[4];
                    if (fread(p, 1, 4, in) != 4) {
                        fclose(in);
                        fclose(out);
                        return error("read phdr failed: %s", sources[i]);
                    }
                    unsigned int p_type = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
                    if (p_type == 3) {
                        is_static = 0;
                        break;
                    }
                }
            }
            if (!is_static) {
                fclose(in);
                fclose(out);
                return error("ELF is dynamically linked (need static): %s", sources[i]);
            }

            if (fseek(in, 0, SEEK_END) != 0) {
                fclose(in);
                fclose(out);
                return error("seek end failed: %s", sources[i]);
            }
        } else if (!memcmp(magic, "\xCE\xFA\xED\xFE", 4) || !memcmp(magic, "\xCF\xFA\xED\xFE", 4)
                   || !memcmp(magic, "\xFE\xED\xFA\xCE", 4) || !memcmp(magic, "\xFE\xED\xFA\xCF", 4)) {
            flags |= UBI_SECTION_MACHO;
            unsigned char mh[sizeof(struct macho_header)];
            if (fseek(in, 0, SEEK_SET) != 0 || fread(mh, 1, sizeof mh, in) != sizeof mh) {
                fclose(in);
                fclose(out);
                return error("failed read Mach-O: %s", sources[i]);
            }

            uint32_t magic_val = (mh[0] << 24) | (mh[1] << 16) | (mh[2] << 8) | mh[3];
            int be = (magic_val == 0xFEEDFACE || magic_val == 0xFEEDFACF);
            /* cputype at 4..7 */
            uint32_t cputype = (mh[4] << 24) | (mh[5] << 16) | (mh[6] << 8) | mh[7];
            uint32_t filetype = (mh[12] << 24) | (mh[13] << 16) | (mh[14] << 8) | mh[15];
            if (be) { /* swap to host little-endian */
                cputype =
                    (cputype >> 24) | ((cputype >> 8) & 0x0000FF00) | ((cputype << 8) & 0x00FF0000) | (cputype << 24);
                filetype = (filetype >> 24) | ((filetype >> 8) & 0x0000FF00) | ((filetype << 8) & 0x00FF0000)
                         | (filetype << 24);
            }
            switch (cputype) {
            case MACHO_CPUTYPE_X86:
                flags |= UBI_SECTION_X86;
                break;
            case MACHO_CPUTYPE_X86_64:
                flags |= UBI_SECTION_X86_64;
                break;
            case MACHO_CPUTYPE_ARM64:
                flags |= UBI_SECTION_AARCH64;
                break;
            case MACHO_CPUTYPE_ARM:
                flags |= UBI_SECTION_ARM;
                break;
            case MACHO_CPUTYPE_POWERPC:
                flags |= UBI_SECTION_PPC;
                break;
            case MACHO_CPUTYPE_MIPS:
                flags |= UBI_SECTION_MIPS;
                break;
            default:
                fclose(in);
                fclose(out);
                return error("unsupported mach-o cpu: %u", cputype);
            }
            if (filetype != MACHO_FILETYPE_EXECUTE) {
                fclose(in);
                fclose(out);
                return error("Mach-O not executable: %s", sources[i]);
            }
            if (fseek(in, 0, SEEK_END) != 0) {
                fclose(in);
                fclose(out);
                return error("seek end failed: %s", sources[i]);
            }
        } else {
            fclose(in);
            fclose(out);
            return error("unknown format: %s", sources[i]);
        }

        long sz = ftell(in);
        if (sz < 0) {
            fclose(in);
            fclose(out);
            return error("ftell failed: %s", sources[i]);
        }
        if (fseek(in, 0, SEEK_SET) != 0) {
            fclose(in);
            fclose(out);
            return error("seek set failed: %s", sources[i]);
        }

        hdr.section_flags[i] = (uint32_t) flags;
        hdr.section_sizes[i] = (uint64_t) sz;

        uint64_t hash = 14695981039346656037ULL;
        unsigned char buf[1 << 16];
        size_t r;
        while ((r = fread(buf, 1, sizeof buf, in)) > 0) {
            for (size_t k = 0; k < r; k++) {
                hash ^= buf[k];
                hash *= 1099511628211ULL;
            }
        }
        if (!feof(in)) {
            fclose(in);
            fclose(out);
            return error("read failed: %s", sources[i]);
        }
        hdr.section_hashes[i] = hash;

        fclose(in);

        hdr.section_offsets[i] = (uint64_t) ftell(out);
        FILE *in2 = fopen(sources[i], "rb");
        if (!in2) {
            fclose(out);
            return error("reopen failed: %s", sources[i]);
        }
        uint64_t remaining = hdr.section_sizes[i];
        while (remaining > 0) {
            size_t chunk = remaining > sizeof buf ? sizeof buf : (size_t) remaining;
            size_t got = fread(buf, 1, chunk, in2);
            if (got != chunk) {
                fclose(in2);
                fclose(out);
                return error("short read copying: %s", sources[i]);
            }
            if (fwrite(buf, 1, got, out) != got) {
                fclose(in2);
                fclose(out);
                return error("short write output");
            }
            remaining -= got;
        }
        fclose(in2);
    }

    if (fseek(out, (long) shebang_len, SEEK_SET) != 0) {
        fclose(out);
        return error("seek header write failed");
    }
    if (ubi_header_write(out, &hdr) != 0) {
        fclose(out);
        return error("write header failed");
    }
    if (chmod(out_path, 0755) != 0) {
        fclose(out);
        return error("chmod failed: %s", out_path);
    }
    fclose(out);
    free(sources);
    return 0;
}

int ubi_inspect(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return error("failed to open binary file: %s", path);

    long start = ftell(f);
    char shebang[32];
    if (fgets(shebang, sizeof shebang, f) && strncmp(shebang, "#!/usr/bin/env ubi", 18) != 0) {
        fseek(f, start, SEEK_SET);
    } else if (feof(f)) {
        fclose(f);
        return error("file too small: %s", path);
    }

    struct ubi_header hdr;
    if (ubi_header_read(f, &hdr) != 0) {
        fclose(f);
        return error("failed to read ubi header.");
    }
    long after = ftell(f);
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, after, SEEK_SET);
    fclose(f);

    if (hdr.magic != UBI_MAGIC)
        return error("invalid ubi binary format.");
    if (hdr.section_count > UBI_MAX_SECTIONS)
        return error("invalid section count");
    for (size_t i = 0; i < hdr.section_count; i++) {
        uint64_t off = hdr.section_offsets[i], sz = hdr.section_sizes[i];
        if (off + sz > (uint64_t) fsize)
            return error("section %zu out of bounds", i);
    }

    printf("UBI Binary Header:\n");
    printf("  Magic: 0x%08x\n", hdr.magic);
    printf("  Version: %u\n", hdr.version);
    printf("  Section Count: %u\n", hdr.section_count);

    for (size_t i = 0; i < hdr.section_count; i++) {
        uint32_t flags = hdr.section_flags[i];
        uint32_t fmt = flags & 0xF0, arch = flags & 0x0F;
        const char *fmts[] = {"?", "ELF", "Mach-O", "PE", "Fat", "?", "?", "Other"};
        const char *archs[] = {"?",    "x86",     "x86_64", "aarch64",     "arm",     "ppc", "ppc64",
                               "mips", "riscv64", "s390x",  "loongarch64", "sparc64", "m68k"};

        printf("  [%zu] %s/%s off=%llu sz=%llu", i, fmts[(fmt >> 4) & 7],
               arch < sizeof(archs) / sizeof(*archs) ? archs[arch] : "?", (unsigned long long) hdr.section_offsets[i],
               (unsigned long long) hdr.section_sizes[i]);

        if (hdr.section_sizes[i] >= 1024ULL * 1024ULL)
            printf(" (%.2fMB)", (double) hdr.section_sizes[i] / (1024.0 * 1024.0));
        else if (hdr.section_sizes[i] >= 1024ULL)
            printf(" (%.2fkB)", (double) hdr.section_sizes[i] / 1024.0);

        printf(" hash=%016llx\n", (unsigned long long) hdr.section_hashes[i]);
    }
    return 0;
}

int help(const char *prog)
{
    fprintf(stderr, "usage: %s [options] [executable...]\n", prog);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  inspect <binary>    Inspect a UBI binary file\n");
    fprintf(stderr, "  -o <output>         Specify output file name\n");
    fprintf(stderr, "  --version           Show version information\n");
    fprintf(stderr, "  --help              Show this help message\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1)
        return help(argv[0]);
    if (argc == 2 && argv[1][0] != '-')
        return execute(argv[1]);

    if (strcmp(argv[1], "inspect") == 0) {
        if (argc < 3)
            return error("no binary specified for inspection.");
        return ubi_inspect(argv[2]);
    }

    char **sources = NULL;
    int count = 0;
    const char *output_file = NULL;
    int output_specified = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-o") == 0) {
                if (output_specified)
                    return error("output file already specified.");
                if (i + 1 >= argc)
                    return error("no output file specified after -o.");
                output_file = argv[++i];
                output_specified = 1;
            } else if (argv[i][1] == '-') {
                if (!strcmp(argv[i], "--help")) {
                    help(argv[0]);
                    return 0;
                } else if (!strcmp(argv[i], "--version")) {
                    puts("ubi version 1.0");
                    return 0;
                } else {
                    return error("unknown option `%s`", argv[i]);
                }
            } else {
                return error("unknown option `%s`", argv[i]);
            }
        } else {
            char **tmp = realloc(sources, sizeof(char *) * (count + 1));
            if (!tmp) {
                free(sources);
                return error("memory allocation failed");
            }
            sources = tmp;
            sources[count++] = argv[i];
        }
    }

    if (count == 0) {
        free(sources);
        return error("no source files specified.");
    }
    if (!output_file)
        output_file = "a.ubi";

    return ubi_merge(sources, count, output_file);
}
