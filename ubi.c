/* ubi.c - universal binary interface
   Copyright (C) 2025 Kacper Fiedorowicz <fiedorowicz.kacper@gmail.com> */

#include <errno.h>
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

#define UBI_VERSION_MAJOR 1
#define UBI_VERSION_MINOR 0
#define UBI_VERSION_PATCH 0

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
#define ELF_MACHINE_X86       0x03
#define ELF_MACHINE_M68K      0x04
#define ELF_MACHINE_MIPS      0x08
#define ELF_MACHINE_PPC       0x14
#define ELF_MACHINE_PPC64     0x15
#define ELF_MACHINE_S390      0x16
#define ELF_MACHINE_ARM       0x28
#define ELF_MACHINE_X86_64    0x3E
#define ELF_MACHINE_AARCH64   0xB7
#define ELF_MACHINE_RISCV     0xF3
#define ELF_MACHINE_LOONGARCH 0x102
#define ELF_FILETYPE_EXEC     0x02
#define ELF_FILETYPE_DYN      0x03

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

#define MACHO_CPUTYPE_X86     0x00000007
#define MACHO_CPUTYPE_ARM     0x0000000C
#define MACHO_CPUTYPE_POWERPC 0x00000012

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
    UBI_SECTION_RISCV32 = 0x0D,
    UBI_SECTION_MIPS64 = 0x0E,
    UBI_SECTION_LOONGARCH32 = 0x0F,

    UBI_SECTION_ELF = 0x10,
    UBI_SECTION_MACHO = 0x20,
    UBI_SECTION_PE = 0x30,
    UBI_SECTION_FAT = 0x40,
    UBI_SECTION_OTHER = 0xF0
};

#define UBI_MAX_SECTIONS   64
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
};

#define RD16LE(p) ((uint16_t) (p)[0] | (uint16_t) (p)[1] << 8)
#define RD16BE(p) ((uint16_t) (p)[1] | (uint16_t) (p)[0] << 8)
#define RD32LE(p) ((uint32_t) (p)[0] | (uint32_t) (p)[1] << 8 | (uint32_t) (p)[2] << 16 | (uint32_t) (p)[3] << 24)
#define RD32BE(p) ((uint32_t) (p)[3] | (uint32_t) (p)[2] << 8 | (uint32_t) (p)[1] << 16 | (uint32_t) (p)[0] << 24)
#define RD64LE(p)                                                                                                      \
    ((uint64_t) (p)[0] | ((uint64_t) (p)[1] << 8) | ((uint64_t) (p)[2] << 16) | ((uint64_t) (p)[3] << 24)              \
     | ((uint64_t) (p)[4] << 32) | ((uint64_t) (p)[5] << 40) | ((uint64_t) (p)[6] << 48) | ((uint64_t) (p)[7] << 56))
#define RD64BE(p)                                                                                                      \
    ((uint64_t) (p)[7] | ((uint64_t) (p)[6] << 8) | ((uint64_t) (p)[5] << 16) | ((uint64_t) (p)[4] << 24)              \
     | ((uint64_t) (p)[3] << 32) | ((uint64_t) (p)[2] << 40) | ((uint64_t) (p)[1] << 48) | ((uint64_t) (p)[0] << 56))

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

    for (size_t i = 0; i < section_count; i++) {
        uint32_t v = htole32(h->section_flags[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < section_count; i++) {
        uint64_t v = htole64(h->section_offsets[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < section_count; i++) {
        uint64_t v = htole64(h->section_sizes[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }
    for (size_t i = 0; i < section_count; i++) {
        uint64_t v = htole64(h->section_hashes[i]);
        if (fwrite(&v, sizeof v, 1, f) != 1)
            return -1;
    }

    return 0;
}

static int ubi_header_read(FILE *f, struct ubi_header *h)
{
    size_t n;
    uint32_t magic;
    uint16_t version, section_count;

    if (fread(&magic, sizeof magic, 1, f) != 1)
        return -1;
    if (fread(&version, sizeof version, 1, f) != 1)
        return -1;
    if (fread(&section_count, sizeof section_count, 1, f) != 1)
        return -1;

    memset(h, 0, sizeof *h);
    h->magic = le32toh(magic);
    h->version = le16toh(version);
    h->section_count = le16toh(section_count);

    if (h->magic != UBI_MAGIC)
        return -1;
    if (h->version != UBI_VERSION)
        return -1;
    if (h->section_count > UBI_MAX_SECTIONS)
        return -1;

    n = h->section_count;
    for (size_t i = 0; i < n; i++) {
        uint32_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->section_flags[i] = le32toh(v);
    }
    for (size_t i = 0; i < n; i++) {
        uint64_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->section_offsets[i] = le64toh(v);
    }
    for (size_t i = 0; i < n; i++) {
        uint64_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->section_sizes[i] = le64toh(v);
    }
    for (size_t i = 0; i < n; i++) {
        uint64_t v;
        if (fread(&v, sizeof v, 1, f) != 1)
            return -1;
        h->section_hashes[i] = le64toh(v);
    }
    return 0;
}

static size_t ubi_header_size(uint16_t version, uint16_t count)
{
    (void) version; /* v2 only */
    /* magic + version + section_count + (flags, offsets, sizes, hashes) * count */
    return sizeof(uint32_t) + 2 * sizeof(uint16_t) + count * (sizeof(uint32_t) + 3 * sizeof(uint64_t));
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 1, 2)))
#endif
static int
ubi_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("ubi: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    return 1;
}

static int ubi_execute(const char *path)
{
    FILE *f;
    int pe_present, platform;
    long start, after_hdr, file_size;
    char shebang[32];
    size_t want_arch;
    struct utsname u;
    struct ubi_header header = {0};

    if ((f = !strcmp(path, "-") ? stdin : fopen(path, "rb")) == NULL)
        return ubi_error("failed to open file: %s", path);

    /* Handle optional shebang */
    start = ftell(f);
    if (fgets(shebang, sizeof shebang, f) == NULL) {
        fclose(f);
        return ubi_error("failed to read file: %s", path);
    }

    if (strncmp(shebang, "#!/usr/bin/env ubi", 14) != 0)
        fseek(f, start, SEEK_SET);

    if (ubi_header_read(f, &header) != 0) {
        fclose(f);
        return ubi_error("failed to read ubi header from file: %s", path);
    }

    if (header.magic != UBI_MAGIC) {
        fclose(f);
        return ubi_error("invalid ubi magic in file: %s", path);
    }

    if (header.version != UBI_VERSION) {
        fclose(f);
        return ubi_error("unsupported ubi version (%u) in file: %s", (unsigned) header.version, path);
    }

    if (header.section_count > UBI_MAX_SECTIONS) {
        fclose(f);
        return ubi_error("invalid section count %u", (unsigned) header.section_count);
    }

    after_hdr = ftell(f);
    if (after_hdr < 0) {
        fclose(f);
        return ubi_error("ftell failed");
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return ubi_error("seek end failed");
    }

    file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return ubi_error("ftell end failed");
    }

    if (fseek(f, after_hdr, SEEK_SET) != 0) {
        fclose(f);
        return ubi_error("seek restore failed");
    }

    pe_present = 0;
    for (size_t i = 0; i < header.section_count; i++) {
        uint64_t off = header.section_offsets[i];
        uint64_t sz = header.section_sizes[i];
        if (sz == 0 || off + sz > (uint64_t) file_size) {
            fclose(f);
            return ubi_error("section %zu out of bounds", i);
        }
    }

    /* Platform / arch detect */
    platform = 0;
    if (uname(&u) != 0) {
        fclose(f);
        return ubi_error("uname failed");
    }

    if (strcmp(u.sysname, "Linux") == 0)
        platform = UBI_PLATFORM_LINUX;
    else if (strcmp(u.sysname, "Darwin") == 0)
        platform = UBI_PLATFORM_MACOS;
    else {
        fclose(f);
        return ubi_error("unsupported platform %s", u.sysname);
    }

    want_arch = 0;
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
    else if (!strcmp(u.machine, "mips64"))
        want_arch = UBI_SECTION_MIPS64;
    else if (!strcmp(u.machine, "riscv32"))
        want_arch = UBI_SECTION_RISCV32;
    else if (!strcmp(u.machine, "riscv64"))
        want_arch = UBI_SECTION_RISCV64;
    else if (!strcmp(u.machine, "s390x"))
        want_arch = UBI_SECTION_S390X;
    else if (!strcmp(u.machine, "loongarch32"))
        want_arch = UBI_SECTION_LOONGARCH32;
    else if (!strcmp(u.machine, "loongarch64"))
        want_arch = UBI_SECTION_LOONGARCH64;
    else if (!strcmp(u.machine, "sparc64"))
        want_arch = UBI_SECTION_SPARC64;
    else if (!strcmp(u.machine, "m68k"))
        want_arch = UBI_SECTION_M68K;
    else {
        fclose(f);
        return ubi_error("unsupported architecture: %s", u.machine);
    }

    for (size_t i = 0; i < header.section_count; i++) {
        const size_t chunk = 1 << 20;
        char cpath[128];
        int out;
        uint64_t off;
        uint64_t sz;
        uint32_t flags = header.section_flags[i];
        uint32_t fmt = flags & 0xF0;
        uint32_t arch = flags & 0x0F;
        uint64_t remaining;
        char *buf;

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
        off = header.section_offsets[i];
        sz = header.section_sizes[i];
        if (fseek(f, (long) off, SEEK_SET) != 0) {
            fclose(f);
            return ubi_error("seek to section failed");
        }

        mkdir("/tmp", 0777); // For containers without /tmp
        mkdir("/tmp/ubi", 0777);

        snprintf(cpath, sizeof cpath, "/tmp/ubi/%016llx", (unsigned long long) header.section_hashes[i]);

        out = open(cpath, O_CREAT | O_WRONLY | O_TRUNC, 0755);
        if (out == -1) {
            fclose(f);
            return ubi_error("open cache failed: %s", strerror(errno));
        }

        remaining = sz;
        if (fseeko(f, (off_t) off, SEEK_SET) != 0) {
            close(out);
            fclose(f);
            return ubi_error("seek failed");
        }

        if ((buf = malloc(chunk)) == NULL) {
            close(out);
            fclose(f);
            return ubi_error("malloc failed");
        }

        while (remaining > 0) {
            size_t rd = remaining > chunk ? chunk : (size_t) remaining;
            if (fread(buf, 1, rd, f) != rd) {
                free(buf);
                close(out);
                fclose(f);
                return ubi_error("short read section");
            }

            if (write(out, buf, rd) != (ssize_t) rd) {
                free(buf);
                close(out);
                fclose(f);
                return ubi_error("short write section");
            }

            remaining -= rd;
        }
        free(buf);
        close(out);
        fclose(f);
        execl(cpath, cpath, NULL);
        return ubi_error("execl failed");
    }

    fclose(f);
    if (pe_present)
        return ubi_error("found matching PE section but Windows platform support is not implemented");

    return ubi_error("no suitable section found in %s", path);
}

static int ubi_merge(char **sources, int count, const char *out_path)
{
    FILE *out;
    size_t shebang_len;
    struct ubi_header hdr;
    const char *shebang = "#!/usr/bin/env ubi\n";

    if (count > UBI_MAX_SECTIONS)
        return ubi_error("too many sections: %d (max %d)", count, UBI_MAX_SECTIONS);

    if ((out = fopen(out_path, "wb")) == NULL)
        return ubi_error("failed to open output file: %s", out_path);

    shebang_len = strlen(shebang);
    if (fwrite(shebang, 1, shebang_len, out) != shebang_len) {
        fclose(out);
        return ubi_error("failed to write shebang");
    }

    memset(&hdr, 0, sizeof hdr);
    hdr.magic = UBI_MAGIC;
    hdr.version = UBI_VERSION;
    hdr.section_count = (uint16_t) count;

    /* Reserve header space */
    if (fseek(out, (long) (shebang_len + ubi_header_size(UBI_VERSION, (uint16_t) count)), SEEK_SET) != 0) {
        fclose(out);
        return ubi_error("failed to reserve header space");
    }

    for (int i = 0; i < count; i++) {
        FILE *in;
        long sz;
        size_t flags = 0;
        size_t r;
        uint64_t hash = 14695981039346656037ULL;
        unsigned char buf[1 << 16];
        unsigned char magic[4];
        FILE *in2;
        uint64_t remaining;

        if ((in = fopen(sources[i], "rb")) == NULL) {
            fclose(out);
            return ubi_error("failed to open source: %s", sources[i]);
        }

        if (fread(magic, 1, 4, in) != 4) {
            fclose(in);
            fclose(out);
            return ubi_error("failed to read magic: %s", sources[i]);
        }

        if (memcmp(magic,
                   "\x7F"
                   "ELF",
                   4)
            == 0) {
            unsigned char ehdr[64];
            uint16_t e_type, e_machine, e_phentsize, e_phnum;
            uint64_t e_phoff = 0;
            int is_64;
            int is_le;
            int archmap[] = {
                [ELF_MACHINE_X86] = UBI_SECTION_X86,         [ELF_MACHINE_X86_64] = UBI_SECTION_X86_64,
                [ELF_MACHINE_AARCH64] = UBI_SECTION_AARCH64, [ELF_MACHINE_ARM] = UBI_SECTION_ARM,
                [ELF_MACHINE_PPC] = UBI_SECTION_PPC,         [ELF_MACHINE_PPC64] = UBI_SECTION_PPC64,
                [ELF_MACHINE_MIPS] = UBI_SECTION_MIPS,       [ELF_MACHINE_RISCV] = UBI_SECTION_RISCV64,
                [ELF_MACHINE_S390] = UBI_SECTION_S390X,      [ELF_MACHINE_LOONGARCH] = UBI_SECTION_LOONGARCH64,
                [ELF_MACHINE_M68K] = UBI_SECTION_M68K};
            int arch = 0;
            int is_static;

            flags |= UBI_SECTION_ELF;

            /* Robust ELF header read (first 64 bytes cover both 32/64) */
            if (fseek(in, 0, SEEK_SET) != 0 || fread(ehdr, 1, 64, in) != 64) {
                fclose(in);
                fclose(out);
                return ubi_error("failed to read ELF header: %s", sources[i]);
            }

            is_64 = (ehdr[4] == 2);
            is_le = (ehdr[5] == 1);

            /* Use endian-aware macros for reading ELF fields, unpacked */
            if (is_le) {
                /* Read e_type and e_machine (object file type and architecture) */
                e_type = (uint16_t) RD16LE(ehdr + 16);
                e_machine = (uint16_t) RD16LE(ehdr + 18);

                if (!is_64) {
                    /* 32-bit ELF: program header offset, entry size, and count */
                    e_phoff = RD32LE(ehdr + 28);
                    e_phentsize = (uint16_t) RD16LE(ehdr + 42);
                    e_phnum = (uint16_t) RD16LE(ehdr + 44);
                } else {
                    /* 64-bit ELF: program header offset, entry size, and count */
                    e_phoff = RD64LE(ehdr + 32);
                    e_phentsize = (uint16_t) RD16LE(ehdr + 54);
                    e_phnum = (uint16_t) RD16LE(ehdr + 56);
                }
            } else {
                /* Big-endian ELF: same fields as above, but use BE macros */
                e_type = (uint16_t) RD16BE(ehdr + 16);
                e_machine = (uint16_t) RD16BE(ehdr + 18);

                if (!is_64) {
                    e_phoff = RD32BE(ehdr + 28);
                    e_phentsize = (uint16_t) RD16BE(ehdr + 42);
                    e_phnum = (uint16_t) RD16BE(ehdr + 44);
                } else {
                    e_phoff = RD64BE(ehdr + 32);
                    e_phentsize = (uint16_t) RD16BE(ehdr + 54);
                    e_phnum = (uint16_t) RD16BE(ehdr + 56);
                }
            }

            if (e_machine < (int) (sizeof(archmap) / sizeof(archmap[0])))
                arch = archmap[e_machine];

            if (!arch) {
                fclose(in);
                fclose(out);
                return ubi_error("unsupported elf machine: %u", e_machine);
            }
            /* Refine by ELF class for multi-ABI machines */
            if (e_machine == ELF_MACHINE_RISCV && !is_64)
                arch = UBI_SECTION_RISCV32;
            if (e_machine == ELF_MACHINE_MIPS && is_64)
                arch = UBI_SECTION_MIPS64;
            if (e_machine == ELF_MACHINE_LOONGARCH && !is_64)
                arch = UBI_SECTION_LOONGARCH32;

            flags |= (size_t) arch;

            if (!(e_type == ELF_FILETYPE_EXEC || e_type == ELF_FILETYPE_DYN)) {
                fclose(in);
                fclose(out);
                return ubi_error("ELF not executable: %s", sources[i]);
            }

            /* Static detection: absence of PT_INTERP (type 3) */
            is_static = 1;
            if (e_phoff && e_phnum && e_phentsize >= 4) {
                for (uint16_t ph = 0; ph < e_phnum; ph++) {
                    unsigned char p[4];
                    unsigned int p_type;
                    uint64_t off = e_phoff + (uint64_t) ph * e_phentsize;

                    if (fseek(in, (long) off, SEEK_SET) != 0) {
                        fclose(in);
                        fclose(out);
                        return ubi_error("seek phdr failed: %s", sources[i]);
                    }

                    if (fread(p, 1, 4, in) != 4) {
                        fclose(in);
                        fclose(out);
                        return ubi_error("read phdr failed: %s", sources[i]);
                    }

                    p_type = (unsigned int) p[0] | ((unsigned int) p[1] << 8) | ((unsigned int) p[2] << 16)
                           | ((unsigned int) p[3] << 24);

                    if (p_type == 3) {
                        is_static = 0;
                        break;
                    }
                }
            }
            if (!is_static) {
                fclose(in);
                fclose(out);
                return ubi_error("ELF is dynamically linked (need static): %s", sources[i]);
            }

            if (fseek(in, 0, SEEK_END) != 0) {
                fclose(in);
                fclose(out);
                return ubi_error("seek end failed: %s", sources[i]);
            }
        } else if (!memcmp(magic, "\xCE\xFA\xED\xFE", 4) || !memcmp(magic, "\xCF\xFA\xED\xFE", 4)
                   || !memcmp(magic, "\xFE\xED\xFA\xCE", 4) || !memcmp(magic, "\xFE\xED\xFA\xCF", 4)) {
            int is_be;
            uint32_t cputype;
            uint32_t filetype;
            uint32_t m;
            uint32_t base;
            unsigned char mh[sizeof(struct macho_header)];
            const uint32_t ABI64 = 0x01000000;

            flags |= UBI_SECTION_MACHO;

            if (fseek(in, 0, SEEK_SET) != 0 || fread(mh, 1, sizeof mh, in) != sizeof mh) {
                fclose(in);
                fclose(out);
                return ubi_error("failed read Mach-O: %s", sources[i]);
            }

            /* Magic values:
               little-end 32: 0xCEFAEDFE
               little-end 64: 0xCFFAEDFE
               big-end   32:  0xFEEDFACE
               big-end   64:  0xFEEDFACF */
            m = (uint32_t) mh[0] << 24 | (uint32_t) mh[1] << 16 | (uint32_t) mh[2] << 8 | mh[3];
            is_be = (m == 0xFEEDFACE || m == 0xFEEDFACF);

            cputype = is_be ? RD32BE(mh + 4) : RD32LE(mh + 4);
            filetype = is_be ? RD32BE(mh + 12) : RD32LE(mh + 12);

            base = cputype & ~ABI64;

            switch (base) {
            case MACHO_CPUTYPE_X86:
                flags |= ((uint32_t) cputype & ABI64) ? UBI_SECTION_X86_64 : UBI_SECTION_X86;
                break;
            case MACHO_CPUTYPE_ARM:
                flags |= ((uint32_t) cputype & ABI64) ? UBI_SECTION_AARCH64 : UBI_SECTION_ARM;
                break;
            case MACHO_CPUTYPE_POWERPC:
                flags |= ((uint32_t) cputype & ABI64) ? UBI_SECTION_PPC64 : UBI_SECTION_PPC;
                break;
            default:
                fclose(in);
                fclose(out);
                return ubi_error("unsupported mach-o cpu: %u (0x%08x)", cputype, cputype);
            }

            /* Check if Mach-O is executable */
            if (filetype != 0x00000002) {
                fclose(in);
                fclose(out);
                return ubi_error("Mach-O not executable: %s", sources[i]);
            }

            if (fseek(in, 0, SEEK_END) != 0) {
                fclose(in);
                fclose(out);
                return ubi_error("seek end failed: %s", sources[i]);
            }
        } else {
            fclose(in);
            fclose(out);
            return ubi_error("unknown format: %s", sources[i]);
        }

        sz = ftell(in);
        if (sz < 0) {
            fclose(in);
            fclose(out);
            return ubi_error("ftell failed: %s", sources[i]);
        }
        if (fseek(in, 0, SEEK_SET) != 0) {
            fclose(in);
            fclose(out);
            return ubi_error("seek set failed: %s", sources[i]);
        }

        hdr.section_flags[i] = (uint32_t) flags;
        hdr.section_sizes[i] = (uint64_t) sz;

        while ((r = fread(buf, 1, sizeof buf, in)) > 0) {
            for (size_t k = 0; k < r; k++) {
                hash ^= buf[k];
                hash *= 1099511628211ULL;
            }
        }
        if (!feof(in)) {
            fclose(in);
            fclose(out);
            return ubi_error("read failed: %s", sources[i]);
        }

        /* Check for hash collisions */
        for (int j = 0; j < i; j++) {
            if (hdr.section_hashes[j] == hash) {
                fclose(in);
                fclose(out);
                return ubi_error("duplicate input content: %s and %s", sources[i], sources[j]);
            }
        }

        hdr.section_hashes[i] = hash;

        fclose(in);

        hdr.section_offsets[i] = (uint64_t) ftell(out);
        if ((in2 = fopen(sources[i], "rb")) == NULL) {
            fclose(out);
            return ubi_error("reopen failed: %s", sources[i]);
        }

        remaining = hdr.section_sizes[i];
        while (remaining > 0) {
            size_t chunk = remaining > sizeof buf ? sizeof buf : (size_t) remaining;
            size_t got = fread(buf, 1, chunk, in2);
            if (got != chunk) {
                fclose(in2);
                fclose(out);
                return ubi_error("short read copying: %s", sources[i]);
            }
            if (fwrite(buf, 1, got, out) != got) {
                fclose(in2);
                fclose(out);
                return ubi_error("short write output");
            }
            remaining -= got;
        }
        fclose(in2);
    }

    if (fseek(out, (long) shebang_len, SEEK_SET) != 0) {
        fclose(out);
        return ubi_error("seek header write failed");
    }

    if (ubi_header_write(out, &hdr) != 0) {
        fclose(out);
        return ubi_error("write header failed");
    }

    if (chmod(out_path, 0755) != 0) {
        fclose(out);
        return ubi_error("chmod failed: %s", out_path);
    }

    fclose(out);
    free(sources);
    return 0;
}

static int copy_section_data(const char *ubi_path, uint64_t src_offset, uint64_t size, FILE *out, uint64_t *new_offset)
{
    FILE *re;
    uint64_t left;
    unsigned char buf[1 << 16];

    if ((re = fopen(ubi_path, "rb")) == NULL)
        return ubi_error("reopen ubi failed");

    if (fseek(re, (long) src_offset, SEEK_SET) != 0) {
        fclose(re);
        return ubi_error("seek section");
    }

    *new_offset = (uint64_t) ftell(out);
    left = size;
    while (left) {
        size_t chunk = left > sizeof buf ? sizeof buf : (size_t) left;

        if (fread(buf, 1, chunk, re) != chunk) {
            fclose(re);
            return ubi_error("read section data");
        }

        if (fwrite(buf, 1, chunk, out) != chunk) {
            fclose(re);
            return ubi_error("write section data");
        }

        left -= chunk;
    }

    fclose(re);
    return 0;
}

static int ubi_inspect(const char *path)
{
    FILE *f;
    char shebang[32];
    long start, after, fsize;
    struct ubi_header hdr;

    if ((f = fopen(path, "rb")) == NULL)
        return ubi_error("failed to open binary file: %s", path);

    start = ftell(f);
    if (fgets(shebang, sizeof shebang, f) && strncmp(shebang, "#!/usr/bin/env ubi", 14) != 0) {
        fseek(f, start, SEEK_SET);
    } else if (feof(f)) {
        fclose(f);
        return ubi_error("file too small: %s", path);
    }

    if (ubi_header_read(f, &hdr) != 0) {
        fclose(f);
        return ubi_error("failed to read ubi header.");
    }

    after = ftell(f);
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, after, SEEK_SET);
    fclose(f);

    if (hdr.magic != UBI_MAGIC)
        return ubi_error("invalid ubi binary format.");

    if (hdr.section_count > UBI_MAX_SECTIONS)
        return ubi_error("invalid section count");

    for (size_t i = 0; i < hdr.section_count; i++) {
        uint64_t off = hdr.section_offsets[i], sz = hdr.section_sizes[i];
        if (off + sz > (uint64_t) fsize)
            return ubi_error("section %zu out of bounds", i);
    }

    printf("%-18s %-12s %-12s %-12s %-12s\n", "hash", "offset", "size", "format", "arch");
    for (size_t i = 0; i < hdr.section_count; i++) {
        uint32_t flags = hdr.section_flags[i];
        uint32_t fmt = flags & 0xF0, arch = flags & 0x0F;
        const char *fmts[] = {"?", "ELF", "Mach-O", "PE", "Fat", "?", "?", "Other"};
        const char *archs[] = {"?",     "x86",     "x86_64",  "aarch64",    "arm",         "ppc",
                               "ppc64", "mips",    "riscv64", "s390x",      "loongarch64", "sparc64",
                               "m68k",  "riscv32", "mips64",  "loongarch32"};

        printf("%-18llx %-12llu %-12llu %-12s %-12s\n", (unsigned long long) hdr.section_hashes[i],
               (unsigned long long) hdr.section_offsets[i], (unsigned long long) hdr.section_sizes[i],
               fmts[(fmt >> 4) & 7], arch < sizeof(archs) / sizeof(*archs) ? archs[arch] : "?");
    }

    for (size_t i = 0; i < hdr.section_count; i++) {
        for (size_t j = i + 1; j < hdr.section_count; j++) {
            if (hdr.section_hashes[i] == hdr.section_hashes[j]) {
                ubi_error("hash collision between section %zu and %zu", i, j);
            }
        }
    }

    return 0;
}

/* Append a new executable section to an existing UBI file */
static int ubi_add(const char *ubi_path, const char *exec_path)
{
    FILE *src, *nexe, *out;
    char shebang[32];
    char tmp_path[512];
    const uint32_t ABI64 = 0x01000000;
    int has_shebang = 0, ok;
    int is_be;
    int32_t cputype;
    long start, new_size;
    size_t hr, new_index, flags;
    size_t nr;
    size_t shebang_len;
    struct ubi_header hdr;
    struct ubi_header newhdr = {0};
    uint32_t m;
    uint64_t hash = 14695981039346656037ULL;
    uint64_t new_hash = 14695981039346656037ULL;
    uint64_t written = 0;
    unsigned char buf2[1 << 16];
    unsigned char hbuf[1 << 16];
    unsigned char magic[4];

    if ((src = fopen(ubi_path, "rb")) == NULL)
        return ubi_error("failed to open ubi file: %s", ubi_path);

    start = ftell(src);
    if (fgets(shebang, sizeof shebang, src) && strncmp(shebang, "#!/usr/bin/env ubi", 14) == 0)
        has_shebang = 1;
    else
        fseek(src, start, SEEK_SET);

    if (ubi_header_read(src, &hdr) != 0) {
        fclose(src);
        return ubi_error("failed to read ubi header: %s", ubi_path);
    }
    if (hdr.magic != UBI_MAGIC || hdr.version != UBI_VERSION) {
        fclose(src);
        return ubi_error("invalid ubi file");
    }
    if (hdr.section_count >= UBI_MAX_SECTIONS) {
        fclose(src);
        return ubi_error("cannot add section: limit reached");
    }

    /* Gather existing section binary data positions (already stored) */
    /* Open new executable and detect format/arch by reusing merge logic (simplified) */
    nexe = fopen(exec_path, "rb");
    if (!nexe) {
        fclose(src);
        return ubi_error("failed to open executable: %s", exec_path);
    }

    if (fread(magic, 1, 4, nexe) != 4) {
        fclose(nexe);
        fclose(src);
        return ubi_error("failed to read magic of new section: %s", exec_path);
    }
    flags = 0;
    ok = 0;

    /* Simple reuse of detection (subset of logic in ubi_merge) */
    if (memcmp(magic,
               "\x7F"
               "ELF",
               4)
        == 0) {
        int arch = 0;
        unsigned char ehdr[64];
        uint16_t e_type;
        uint16_t e_machine;
        int archmap[] = {[ELF_MACHINE_X86] = UBI_SECTION_X86,         [ELF_MACHINE_X86_64] = UBI_SECTION_X86_64,
                         [ELF_MACHINE_AARCH64] = UBI_SECTION_AARCH64, [ELF_MACHINE_ARM] = UBI_SECTION_ARM,
                         [ELF_MACHINE_PPC] = UBI_SECTION_PPC,         [ELF_MACHINE_PPC64] = UBI_SECTION_PPC64,
                         [ELF_MACHINE_MIPS] = UBI_SECTION_MIPS,       [ELF_MACHINE_RISCV] = UBI_SECTION_RISCV64,
                         [ELF_MACHINE_S390] = UBI_SECTION_S390X,      [ELF_MACHINE_LOONGARCH] = UBI_SECTION_LOONGARCH64,
                         [ELF_MACHINE_M68K] = UBI_SECTION_M68K};

        flags |= UBI_SECTION_ELF;

        fseek(nexe, 0, SEEK_SET);
        if (fread(ehdr, 1, 64, nexe) != 64) {
            fclose(nexe);
            fclose(src);
            return ubi_error("failed ELF hdr read: %s", exec_path);
        }

        e_type = (uint16_t) (ehdr[16] | (ehdr[17] << 8));
        e_machine = (uint16_t) (ehdr[18] | (ehdr[19] << 8));

        if (e_machine < (int) (sizeof(archmap) / sizeof(archmap[0])))
            arch = archmap[e_machine];

        if (!arch) {
            fclose(nexe);
            fclose(src);
            return ubi_error("unsupported elf machine in add: %u", e_machine);
        }

        /* Refine by ELF class for multi-ABI machines */
        if (e_machine == ELF_MACHINE_RISCV && (ehdr[4] != 2))
            arch = UBI_SECTION_RISCV32;
        if (e_machine == ELF_MACHINE_MIPS && (ehdr[4] == 2))
            arch = UBI_SECTION_MIPS64;
        if (e_machine == ELF_MACHINE_LOONGARCH && (ehdr[4] != 2))
            arch = UBI_SECTION_LOONGARCH32;
        if (!(e_type == ELF_FILETYPE_EXEC || e_type == ELF_FILETYPE_DYN)) {
            fclose(nexe);
            fclose(src);
            return ubi_error("ELF not executable: %s", exec_path);
        }

        flags |= (size_t) arch;

        ok = 1;
        fseek(nexe, 0, SEEK_END);
    } else if (!memcmp(magic, "\xCE\xFA\xED\xFE", 4) || !memcmp(magic, "\xCF\xFA\xED\xFE", 4)
               || !memcmp(magic, "\xFE\xED\xFA\xCE", 4) || !memcmp(magic, "\xFE\xED\xFA\xCF", 4)) {
        uint32_t base;
        unsigned char mh[28];

        flags |= UBI_SECTION_MACHO;
        fseek(nexe, 0, SEEK_SET);
        if (fread(mh, 1, sizeof mh, nexe) != sizeof mh) {
            fclose(nexe);
            fclose(src);
            return ubi_error("Mach-O hdr read failed: %s", exec_path);
        }
        m = (uint32_t) mh[0] << 24 | (uint32_t) mh[1] << 16 | (uint32_t) mh[2] << 8 | mh[3];
        is_be = (m == 0xFEEDFACE || m == 0xFEEDFACF);
        cputype = (int32_t) (is_be ? RD32BE(mh + 4) : RD32LE(mh + 4));
        base = (uint32_t) cputype & ~ABI64;
        switch (base) {
        case MACHO_CPUTYPE_X86:
            flags |= (((uint32_t) cputype & ABI64) ? UBI_SECTION_X86_64 : UBI_SECTION_X86);
            ok = 1;
            break;
        case MACHO_CPUTYPE_ARM:
            flags |= ((uint32_t) cputype & ABI64) ? UBI_SECTION_AARCH64 : UBI_SECTION_ARM;
            ok = 1;
            break;
        case MACHO_CPUTYPE_POWERPC:
            flags |= ((uint32_t) cputype & ABI64) ? UBI_SECTION_PPC64 : UBI_SECTION_PPC;
            ok = 1;
            break;
        default:
            break;
        }
        fseek(nexe, 0, SEEK_END);
    } else {
        fclose(nexe);
        fclose(src);
        return ubi_error("unknown new section format: %s", exec_path);
    }
    if (!ok) {
        fclose(nexe);
        fclose(src);
        return ubi_error("unsupported new section format/arch: %s", exec_path);
    }
    new_size = ftell(nexe);
    if (new_size < 0) {
        fclose(nexe);
        fclose(src);
        return ubi_error("ftell failed new exec");
    }
    /* Compute hash of new executable for duplicate detection */
    fseek(nexe, 0, SEEK_SET);
    while ((hr = fread(hbuf, 1, sizeof hbuf, nexe)) > 0) {
        for (size_t k = 0; k < hr; k++) {
            new_hash ^= hbuf[k];
            new_hash *= 1099511628211ULL;
        }
    }
    if (!feof(nexe)) {
        fclose(nexe);
        fclose(src);
        return ubi_error("read failed: %s", exec_path);
    }
    /* Check for duplicate content by hash */
    for (size_t i = 0; i < hdr.section_count; i++) {
        if (hdr.section_hashes[i] == new_hash) {
            fclose(nexe);
            fclose(src);
            return ubi_error("duplicate section: identical content already present");
        }
    }
    /* Rewind for writing new section */
    fseek(nexe, 0, SEEK_SET);

    /* Build output in temp file */
    snprintf(tmp_path, sizeof tmp_path, "%s.tmp", ubi_path);

    if ((out = fopen(tmp_path, "wb"))) {
        fclose(nexe);
        fclose(src);
        return ubi_error("open temp failed");
    }

    /* Write shebang if present */
    if (has_shebang) {
        fputs("#!/usr/bin/env ubi\n", out);
    }

    newhdr.magic = UBI_MAGIC;
    newhdr.version = UBI_VERSION;
    newhdr.section_count = hdr.section_count + 1;

    /* Reserve space */
    shebang_len = has_shebang ? strlen("#!/usr/bin/env ubi\n") : 0;
    if (fseek(out, (long) (shebang_len + ubi_header_size(UBI_VERSION, newhdr.section_count)), SEEK_SET) != 0) {
        fclose(out);
        fclose(nexe);
        fclose(src);
        return ubi_error("reserve failed");
    }

    /* Copy old sections in order (deduplicated via helper) */
    for (size_t i = 0; i < hdr.section_count; i++) {
        newhdr.section_flags[i] = hdr.section_flags[i];
        newhdr.section_sizes[i] = hdr.section_sizes[i];
        newhdr.section_hashes[i] = hdr.section_hashes[i];

        if (copy_section_data(ubi_path, hdr.section_offsets[i], hdr.section_sizes[i], out, &newhdr.section_offsets[i])
            != 0) {
            fclose(out);
            fclose(nexe);
            fclose(src);
            return 1;
        }
    }

    /* Append new section */
    new_index = hdr.section_count;
    newhdr.section_flags[new_index] = (uint32_t) flags;
    newhdr.section_offsets[new_index] = (uint64_t) ftell(out);

    while ((nr = fread(buf2, 1, sizeof buf2, nexe)) > 0) {
        for (size_t k = 0; k < nr; k++) {
            hash ^= buf2[k];
            hash *= 1099511628211ULL;
        }
        if (fwrite(buf2, 1, nr, out) != nr) {
            fclose(out);
            fclose(nexe);
            fclose(src);
            return ubi_error("write new section failed");
        }
        written += nr;
    }
    if (!feof(nexe)) {
        fclose(out);
        fclose(nexe);
        fclose(src);
        return ubi_error("read new section failed");
    }

    newhdr.section_sizes[new_index] = written;
    newhdr.section_hashes[new_index] = hash;

    /* Write header */
    if (fseek(out, (long) shebang_len, SEEK_SET) != 0) {
        fclose(out);
        fclose(nexe);
        fclose(src);
        return ubi_error("seek header failed");
    }
    if (ubi_header_write(out, &newhdr) != 0) {
        fclose(out);
        fclose(nexe);
        fclose(src);
        return ubi_error("header write failed");
    }
    fclose(out);
    fclose(nexe);
    fclose(src);

    if (rename(tmp_path, ubi_path) != 0) {
        return ubi_error("rename failed (temp to final)");
    }

    if (chmod(ubi_path, 0755) != 0) {
        return ubi_error("chmod failed: %s", ubi_path);
    }

    return 0;
}

/* Remove a section (by index) from a UBI file */
static int ubi_remove(const char *ubi_path, uint64_t target_hash)
{
    long start;
    int index;
    size_t out_i;
    struct stat st;
    FILE *src, *out;
    size_t shebang_len;
    char shebang[32];
    char tmp_path[512];
    int has_shebang = 0;
    mode_t orig_mode = 0;
    struct ubi_header hdr;
    struct ubi_header newhdr = {0};

    if (stat(ubi_path, &st) == 0)
        orig_mode = st.st_mode & 07777;

    if ((src = fopen(ubi_path, "rb")) == NULL)
        return ubi_error("failed to open ubi file: %s", ubi_path);

    start = ftell(src);
    if (fgets(shebang, sizeof shebang, src) && strncmp(shebang, "#!/usr/bin/env ubi", 14) == 0)
        has_shebang = 1;
    else
        fseek(src, start, SEEK_SET);

    if (ubi_header_read(src, &hdr) != 0) {
        fclose(src);
        return ubi_error("failed to read header");
    }

    index = -1;
    for (size_t i = 0; i < hdr.section_count; i++) {
        if (hdr.section_hashes[i] == target_hash) {
            index = (int) i;
            break;
        }
    }
    if (index == -1) {
        fclose(src);
        return ubi_error("no section with hash %016llx", (unsigned long long) target_hash);
    }

    snprintf(tmp_path, sizeof tmp_path, "%s.tmp", ubi_path);
    out = fopen(tmp_path, "wb");
    if (!out) {
        fclose(src);
        return ubi_error("open temp failed");
    }
    shebang_len = has_shebang ? strlen("#!/usr/bin/env ubi\n") : 0;
    if (has_shebang)
        fputs("#!/usr/bin/env ubi\n", out);

    newhdr.magic = UBI_MAGIC;
    newhdr.version = UBI_VERSION;
    newhdr.section_count = (uint16_t) (hdr.section_count - 1);

    if (fseek(out, (long) (shebang_len + ubi_header_size(UBI_VERSION, newhdr.section_count)), SEEK_SET) != 0) {
        fclose(out);
        fclose(src);
        return ubi_error("reserve failed");
    }

    /* Copy all except index (using helper) */
    out_i = 0;
    for (size_t i = 0; i < hdr.section_count; i++) {
        if ((int) i == index)
            continue;
        newhdr.section_flags[out_i] = hdr.section_flags[i];
        newhdr.section_sizes[out_i] = hdr.section_sizes[i];
        newhdr.section_hashes[out_i] = hdr.section_hashes[i];

        if (copy_section_data(ubi_path, hdr.section_offsets[i], hdr.section_sizes[i], out,
                              &newhdr.section_offsets[out_i])
            != 0) {
            fclose(out);
            fclose(src);
            return 1;
        }
        out_i++;
    }

    if (fseek(out, (long) shebang_len, SEEK_SET) != 0) {
        fclose(out);
        fclose(src);
        return ubi_error("seek hdr write");
    }

    if (ubi_header_write(out, &newhdr) != 0) {
        fclose(out);
        fclose(src);
        return ubi_error("hdr write fail");
    }

    fclose(out);
    fclose(src);

    if (rename(tmp_path, ubi_path) != 0)
        return ubi_error("rename failed");

    if (orig_mode)
        chmod(ubi_path, orig_mode);

    return 0;
}

static int help(const char *prog)
{
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  %s [executable ...]            (create UBI from executables)\n", prog);
    fprintf(stderr, "  %s inspect <ubi>               Inspect a UBI binary\n", prog);
    fprintf(stderr, "  %s add <ubi> <executable>      Append a new section\n", prog);
    fprintf(stderr, "  %s remove <ubi> <hash>         Remove section by hash\n", prog);

    fprintf(stderr, "options:\n");
    fprintf(stderr, "  -o <output>                    Output file name when creating\n");
    fprintf(stderr, "  --version                      Show version\n");
    fprintf(stderr, "  --help                         Show help\n");
    return 0;
}

int main(int argc, char **argv)
{
    char **sources = NULL;
    int count = 0;
    const char *output_file = NULL;
    int output_specified = 0;

    if (argc == 1) {
        return ubi_execute("-");
    }

    /* Direct execution shortcut: ubi <file> */
    if (argc == 2 && argv[1][0] != '-') {
        return ubi_execute(argv[1]);
    }

    if (strcmp(argv[1], "inspect") == 0) {
        if (argc < 3)
            return ubi_error("no binary specified for inspection.");

        return ubi_inspect(argv[2]);
    } else if (strcmp(argv[1], "add") == 0) {
        if (argc != 4)
            return ubi_error("usage: %s add <ubi> <executable>", argv[0]);

        return ubi_add(argv[2], argv[3]);
    } else if (strcmp(argv[1], "remove") == 0) {
        char *endp;
        unsigned long long h;

        if (argc != 4)
            return ubi_error("usage: %s remove <ubi> <hash>", argv[0]);

        endp = NULL;
        h = strtoull(argv[3], &endp, 16);
        if (!endp || *endp)
            return ubi_error("invalid hash: %s", argv[3]);

        return ubi_remove(argv[2], (uint64_t) h);
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-o") == 0) {
                if (output_specified)
                    return ubi_error("output file already specified.");
                if (i + 1 >= argc)
                    return ubi_error("no output file specified after -o.");
                output_file = argv[++i];
                output_specified = 1;
            } else if (strcmp(argv[i], "-h") == 0) {
                return help(argv[0]);
            } else if (argv[i][1] == '-') {
                if (!strcmp(argv[i], "--help"))
                    return help(argv[0]);
                else if (!strcmp(argv[i], "--version")) {
                    printf("ubi (universal binary interface) version %d.%d.%d\n", UBI_VERSION_MAJOR, UBI_VERSION_MINOR,
                           UBI_VERSION_PATCH);
                    return 0;
                } else {
                    return ubi_error("unknown option `%s`", argv[i]);
                }
            } else {
                return ubi_error("unknown option `%s`", argv[i]);
            }
        } else {
            char **tmp = realloc(sources, sizeof(char *) * (size_t) (count + 1));
            if (!tmp) {
                free(sources);
                return ubi_error("memory allocation failed");
            }
            sources = tmp;
            sources[count++] = argv[i];
        }
    }
    if (count == 0) {
        free(sources);
        return ubi_error("no source files specified.");
    }

    if (!output_file)
        output_file = "a.ubi";

    return ubi_merge(sources, count, output_file);
}
