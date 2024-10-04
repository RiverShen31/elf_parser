#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* How to extract and insert information held in the st_info field.  */

#define ELF32_ST_BIND(val)		(((unsigned char) (val)) >> 4)
#define ELF32_ST_TYPE(val)		((val) & 0xf)
#define ELF32_ST_INFO(bind, type)	(((bind) << 4) + ((type) & 0xf))

/* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
#define ELF64_ST_BIND(val)		ELF32_ST_BIND (val)
#define ELF64_ST_TYPE(val)		ELF32_ST_TYPE (val)
#define ELF64_ST_INFO(bind, type)	ELF32_ST_INFO ((bind), (type))

/* How to extract and insert information held in the st_other field.  */
#define ELF32_ST_VISIBILITY(o)	((o) & 0x03)
/* For ELF64 the definitions are the same.  */
#define ELF64_ST_VISIBILITY(o)	ELF32_ST_VISIBILITY (o)

#define EI_NIDENT 16
#define SHF_WRITE      0x1     // Section contains writable data
#define SHF_ALLOC      0x2     // Section occupies memory during execution
#define SHF_EXECINSTR  0x4     // Section contains executable instructions
#define SHF_MERGE      0x10    // Section may be merged
#define SHF_STRINGS    0x20    // Section contains string table
#define SHF_INFO_LINK  0x40    // Section holds section index link

// Segment types
#define PT_NULL          0       // Program header table entry unused
#define PT_LOAD          1       // Loadable segment
#define PT_DYNAMIC       2       // Dynamic linking information
#define PT_INTERP        3       // Program interpreter
#define PT_NOTE          4       // Auxiliary information
#define PT_SHLIB         5       // Reserved
#define PT_PHDR          6       // Entry for header table
#define PT_GNU_STACK     0x6474e551 // Stack segment
#define PT_GNU_RELRO     0x6474e552 // Read-only after relocation
#define PT_GNU_PROPERTY	0x6474e553	/* GNU property */
#define PT_GNU_EH_FRAME  0x65041580 // EH frame segment

// Flags for segments
#define PF_X             0x1     // Executable
#define PF_W             0x2     // Writable
#define PF_R             0x4     // Readable

#define DT_NULL		0		/* Marks end of dynamic section */
#define DT_NEEDED	1		/* Name of needed library */
#define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
#define DT_PLTGOT	3		/* Processor defined value */
#define DT_HASH		4		/* Address of symbol hash table */
#define DT_STRTAB	5		/* Address of string table */
#define DT_SYMTAB	6		/* Address of symbol table */
#define DT_RELA		7		/* Address of Rela relocs */
#define DT_RELASZ	8		/* Total size of Rela relocs */
#define DT_RELAENT	9		/* Size of one Rela reloc */
#define DT_STRSZ	10		/* Size of string table */
#define DT_SYMENT	11		/* Size of one symbol table entry */
#define DT_INIT		12		/* Address of init function */
#define DT_FINI		13		/* Address of termination function */
#define DT_SONAME	14		/* Name of shared object */
#define DT_RPATH	15		/* Library search path (deprecated) */
#define DT_SYMBOLIC	16		/* Start symbol search here */
#define DT_REL		17		/* Address of Rel relocs */
#define DT_RELSZ	18		/* Total size of Rel relocs */
#define DT_RELENT	19		/* Size of one Rel reloc */
#define DT_PLTREL	20		/* Type of reloc in PLT */
#define DT_DEBUG	21		/* For debugging; unspecified */
#define DT_TEXTREL	22		/* Reloc might modify .text */
#define DT_JMPREL	23		/* Address of PLT relocs */
#define	DT_BIND_NOW	24		/* Process relocations of object */
#define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	29		/* Library search path */
#define DT_FLAGS	30		/* Flags for the object being loaded */
#define DT_ENCODING	32		/* Start of encoded range */
#define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33		/* size in bytes of DT_PREINIT_ARRAY */
#define DT_SYMTAB_SHNDX	34		/* Address of SYMTAB_SHNDX section */
#define DT_RELRSZ	35		/* Total size of RELR relative relocations */
#define DT_RELR		36		/* Address of RELR relative relocations */
#define DT_RELRENT	37		/* Size of one RELR relative relocaction */
#define	DT_NUM		38		/* Number used */
#define DT_LOOS		0x6000000d	/* Start of OS-specific */
#define DT_HIOS		0x6ffff000	/* End of OS-specific */
#define DT_LOPROC	0x70000000	/* Start of processor-specific */
#define DT_HIPROC	0x7fffffff	/* End of processor-specific */
#define	DT_PROCNUM	DT_MIPS_NUM	/* Most used by any processor */
#define DT_GNU_HASH	0x6ffffef5
#define DT_VERSYM	0x6ffffff0
#define DT_FLAGS_1	0x6ffffffb
#define DT_VERNEED	0x6ffffffe
#define	DT_VERNEEDNUM	0x6fffffff
#define DT_RELACOUNT	0x6ffffff9

/* AMD x86-64 relocations.  */
#define R_X86_64_NONE		0	/* No reloc */
#define R_X86_64_64		1	/* Direct 64 bit  */
#define R_X86_64_PC32		2	/* PC relative 32 bit signed */
#define R_X86_64_GOT32		3	/* 32 bit GOT entry */
#define R_X86_64_PLT32		4	/* 32 bit PLT address */
#define R_X86_64_COPY		5	/* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT	6	/* Create GOT entry */
#define R_X86_64_JUMP_SLOT	7	/* Create PLT entry */
#define R_X86_64_RELATIVE	8	/* Adjust by program base */
#define R_X86_64_GOTPCREL	9	

#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)

#define SHT_RELA	  4		/* Relocation entries with addends */

#define SHT_DYNSYM	  11

#define STT_NOTYPE	0		/* Symbol type is unspecified */
#define STT_OBJECT	1		/* Symbol is a data object */
#define STT_FUNC	2		/* Symbol is a code object */
#define STT_SECTION	3		/* Symbol associated with a section */
#define STT_FILE	4		/* Symbol's name is file name */
#define STT_COMMON	5		/* Symbol is a common data object */
#define STT_TLS		6		/* Symbol is thread-local data object*/
#define	STT_NUM		7		/* Number of defined types.  */
#define STT_LOOS	10		/* Start of OS-specific */
#define STT_GNU_IFUNC	10		/* Symbol is indirect code object */
#define STT_HIOS	12		/* End of OS-specific */
#define STT_LOPROC	13		/* Start of processor-specific */
#define STT_HIPROC	15	

/* Legal values for ST_BIND subfield of st_info (symbol binding).  */

#define STB_LOCAL	0		/* Local symbol */
#define STB_GLOBAL	1		/* Global symbol */
#define STB_WEAK	2		/* Weak symbol */
#define	STB_NUM		3		/* Number of defined types.  */
#define STB_LOOS	10		/* Start of OS-specific */
#define STB_GNU_UNIQUE	10		/* Unique symbol.  */
#define STB_HIOS	12		/* End of OS-specific */
#define STB_LOPROC	13		/* Start of processor-specific */
#define STB_HIPROC	15

/* Symbol visibility specification encoded in the st_other field.  */
#define STV_DEFAULT	0		/* Default symbol visibility rules */
#define STV_INTERNAL	1		/* Processor specific hidden class */
#define STV_HIDDEN	2		/* Sym unavailable in other modules */
#define STV_PROTECTED	3		/* Not preemptible, not exported */

/* Special section indices.  */

#define SHN_UNDEF	0		/* Undefined section */
#define SHN_LORESERVE	0xff00		/* Start of reserved indices */
#define SHN_LOPROC	0xff00		/* Start of processor-specific */
#define SHN_BEFORE	0xff00		/* Order section before all others
					   (Solaris).  */
#define SHN_AFTER	0xff01		/* Order section after all others
					   (Solaris).  */
#define SHN_HIPROC	0xff1f		/* End of processor-specific */
#define SHN_LOOS	0xff20		/* Start of OS-specific */
#define SHN_HIOS	0xff3f		/* End of OS-specific */
#define SHN_ABS		0xfff1		/* Associated symbol is absolute */
#define SHN_COMMON	0xfff2		/* Associated symbol is common */
#define SHN_XINDEX	0xffff		/* Index is in extra table.  */
#define SHN_HIRESERVE	0xffff		/* End of reserved indices */


#define SHT_SYMTAB	  2		/* Symbol table */

// Enum for ELF Class
typedef enum {
    ELFCLASSNONE = 0,
    ELFCLASS32 = 1,
    ELFCLASS64 = 2
} ElfClass;

// Enum for Data Encoding
typedef enum {
    ELFDATANONE = 0,
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2
} ElfData;

// Enum for OS/ABI
typedef enum {
    ELFOSABI_NONE = 0,
    ELFOSABI_SYSV = 0,
    ELFOSABI_HPUX = 1,
    ELFOSABI_NETBSD = 2,
    ELFOSABI_LINUX = 3,
    ELFOSABI_SOLARIS = 6,
    ELFOSABI_AIX = 7,
    ELFOSABI_IRIX = 8,
    ELFOSABI_FREEBSD = 9,
    ELFOSABI_OPENBSD = 12,
    ELFOSABI_OPENVMS = 13,
    ELFOSABI_NONSTOP = 14,
    ELFOSABI_AROS = 15,
    ELFOSABI_FENIXOS = 16
} ElfOSABI;

// Enum for Type
typedef enum {
    ET_NONE = 0,
    ET_REL = 1,
    ET_EXEC = 2,
    ET_DYN = 3,
    ET_CORE = 4,
    ET_LOOS = 0xff00,
    ET_HIOS = 0xffff,
    ET_LOPROC = 0xff01,
    ET_HIPROC = 0xff02
} ElfType;

// ELF header structure
typedef struct {
    unsigned char e_ident[EI_NIDENT]; // ELF Identification
    uint16_t e_type;                   // Object file type
    uint16_t e_machine;                // Machine type
    uint32_t e_version;                // Object file version
    uint64_t e_entry;                  // Entry point address
    uint64_t e_phoff;                  // Program header offset
    uint64_t e_shoff;                  // Section header offset
    uint32_t e_flags;                  // Processor-specific flags
    uint16_t e_ehsize;                 // ELF header size
    uint16_t e_phentsize;              // Program header entry size
    uint16_t e_phnum;                  // Program header entry count
    uint16_t e_shentsize;              // Section header entry size
    uint16_t e_shnum;                  // Section header entry count
    uint16_t e_shstrndx;               // Section header string table index
} Elf64_Ehdr;

// Section header structure
typedef struct {
    uint32_t sh_name;      // Section name (string tbl index)
    uint32_t sh_type;      // Section type
    uint64_t sh_flags;     // Section flags
    uint64_t sh_addr;      // Section virtual addr at execution
    uint64_t sh_offset;    // Section file offset
    uint64_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint64_t sh_addralign; // Section alignment
    uint64_t sh_entsize;   // Entry size if section holds table
} Elf64_Shdr;

// Program header structure
typedef struct {
    uint32_t p_type;   // Type of segment
    uint32_t p_flags;  // Segment attributes
    uint64_t p_offset; // Offset in file
    uint64_t p_vaddr;  // Virtual address in memory
    uint64_t p_paddr;  // Physical address (not used)
    uint64_t p_filesz; // Size of segment in file
    uint64_t p_memsz;  // Size of segment in memory
    uint64_t p_align;  // Alignment
} Elf64_Phdr;

typedef struct {
  int64_t d_tag;		/* entry tag value */
  union {
    uint64_t d_val;
    uint64_t d_ptr;
  } d_un;
} Elf64_Dyn;

typedef struct
{
  uint64_t	r_offset;		/* Address */
  uint64_t	r_info;			/* Relocation type and symbol index */
  int64_t	r_addend;		/* Addend */
} Elf64_Rela;


typedef struct
{
  uint32_t	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  uint16_t	st_shndx;		/* Section index */
  uint64_t	st_value;		/* Symbol value */
  uint64_t	st_size;		/* Symbol size */
} Elf64_Sym;

// Function to get ELF class as a string
const char* elf_class_to_string(ElfClass class) {
    switch (class) {
        case ELFCLASS32: return "ELF32";
        case ELFCLASS64: return "ELF64";
        default: return "Unknown";
    }
}

// Function to get data encoding as a string
const char* elf_data_to_string(ElfData data) {
    switch (data) {
        case ELFDATA2LSB: return "2's complement, little endian";
        case ELFDATA2MSB: return "2's complement, big endian";
        default: return "Unknown";
    }
}

// Function to get OS/ABI as a string
const char* elf_osabi_to_string(ElfOSABI abi) {
    switch (abi) {
        case ELFOSABI_SYSV: return "UNIX - System V";
        case ELFOSABI_HPUX: return "HP-UX";
        case ELFOSABI_NETBSD: return "NetBSD";
        case ELFOSABI_LINUX: return "Linux";
        case ELFOSABI_SOLARIS: return "Solaris";
        case ELFOSABI_AIX: return "AIX";
        case ELFOSABI_IRIX: return "IRIX";
        case ELFOSABI_FREEBSD: return "FreeBSD";
        case ELFOSABI_OPENBSD: return "OpenBSD";
        case ELFOSABI_OPENVMS: return "OpenVMS";
        case ELFOSABI_NONSTOP: return "NonStop Kernel";
        case ELFOSABI_AROS: return "AROS";
        case ELFOSABI_FENIXOS: return "Fenix OS";
        default: return "Unknown";
    }
}

// Function to get type as a string
const char* elf_type_to_string(ElfType type) {
    switch (type) {
        case ET_NONE: return "NONE (No file type)";
        case ET_REL: return "REL (Relocatable file)";
        case ET_EXEC: return "EXEC (Executable file)";
        case ET_DYN: return "DYN (Shared object file)";
        case ET_CORE: return "CORE (Core file)";
        case ET_LOOS: return "LOOS (OS-specific)";
        case ET_HIOS: return "HIOS (OS-specific)";
        case ET_LOPROC: return "LOPROC (Processor-specific)";
        case ET_HIPROC: return "HIPROC (Processor-specific)";
        default: return "Unknown";
    }
}

// Function to print the ELF header
void print_elf_header(Elf64_Ehdr *header) {
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf("%02x ", header->e_ident[i]);
    }
    printf("\n");
    printf("  Class:                             %s\n", elf_class_to_string(header->e_ident[4]));
    printf("  Data:                              %s\n", elf_data_to_string(header->e_ident[5]));
    printf("  Version:                           %u (current)\n", header->e_version);
    printf("  OS/ABI:                            %s\n", elf_osabi_to_string(header->e_ident[7]));
    printf("  ABI Version:                       %u\n", header->e_ident[8]);
    printf("  Type:                              %s\n", elf_type_to_string(header->e_type));
    printf("  Machine:                           %u\n", header->e_machine);
    printf("  Version:                           0x%x\n", header->e_version);
    printf("  Entry point address:               0x%lx\n", header->e_entry);
    printf("  Start of program headers:           %lu (bytes into file)\n", header->e_phoff);
    printf("  Start of section headers:           %lu (bytes into file)\n", header->e_shoff);
    printf("  Flags:                             0x%x\n", header->e_flags);
    printf("  Size of this header:               %u (bytes)\n", header->e_ehsize);
    printf("  Size of program headers:            %u (bytes)\n", header->e_phentsize);
    printf("  Number of program headers:          %u\n", header->e_phnum);
    printf("  Size of section headers:            %u (bytes)\n", header->e_shentsize);
    printf("  Number of section headers:          %u\n", header->e_shnum);
    printf("  Section header string table index:  %u\n", header->e_shstrndx);
}

// Get Section name from the string table
const char *get_section_name(int fd,Elf64_Shdr *section_headers, int index, Elf64_Ehdr *header) {
  int shstrtab_index = header->e_shstrndx;

  Elf64_Shdr shstrtab_header = section_headers[shstrtab_index];
  char *name = malloc(shstrtab_header.sh_size);
  lseek(fd, shstrtab_header.sh_offset, SEEK_SET);
  read(fd, name, shstrtab_header.sh_size);

  const char *section_name = name + section_headers[index].sh_name;
  free(name); // Free the allocated memory
  return section_name;
}

// Function to print section headers
void print_section_headers(int fd, Elf64_Ehdr *header) {
    Elf64_Shdr *section_headers = malloc(header->e_shnum * header->e_shentsize);
    lseek(fd, header->e_shoff, SEEK_SET);
    read(fd, section_headers, header->e_shnum * header->e_shentsize);

    printf("\nSection Headers:\n");
    printf("  [Nr] Name              Type             Address           Offset\n");
    printf("       Size              EntSize          Flags  Link  Info  Align\n");

    for (int i = 0; i < header->e_shnum; i++) {
        const char *name = get_section_name(fd, section_headers, i, header);
        printf("  [%2d] %-17s %-15u %016lx %016lx\n",
               i, name, section_headers[i].sh_type,
               section_headers[i].sh_addr,
               section_headers[i].sh_offset);
        printf("       %016lx %016lx %c%c%c%c%c%c  %u  %u  %lu\n",
               section_headers[i].sh_size,
               section_headers[i].sh_entsize,
               (section_headers[i].sh_flags & SHF_WRITE) ? 'W' : '-',
               (section_headers[i].sh_flags & SHF_ALLOC) ? 'A' : '-',
               (section_headers[i].sh_flags & SHF_EXECINSTR) ? 'X' : '-',
               (section_headers[i].sh_flags & SHF_MERGE) ? 'M' : '-',
               (section_headers[i].sh_flags & SHF_STRINGS) ? 'S' : '-',
               (section_headers[i].sh_flags & SHF_INFO_LINK) ? 'I' : '-',
               section_headers[i].sh_link,
               section_headers[i].sh_info,
               section_headers[i].sh_addralign);
    }

    free(section_headers);
}
// Function to get the type as a string
const char *get_segment_type_str(uint32_t type) {
    switch (type) {
        case PT_PHDR: return "PHDR";
        case PT_INTERP: return "INTERP";
        case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_NOTE: return "NOTE";
        case PT_GNU_PROPERTY: return "GNU_PROPERTY";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK: return "GNU_STACK";
        case PT_GNU_RELRO: return "GNU_RELRO";
        default: return "UNKNOWN";
    }
}

// Function to get the flags as a string
void get_flags(uint32_t flags, char *buffer) {
    buffer[0] = '\0'; // Initialize buffer

    if (flags & PF_R) {
        strcat(buffer, "R ");
    }
    if (flags & PF_W) {
        strcat(buffer, "W ");
    }
    if (flags & PF_X) {
        strcat(buffer, "E ");
    }
}

// Assuming get_flags and get_segment_type_str are defined elsewhere

void print_program_headers(int fd, Elf64_Ehdr *header) {
    // Read program headers
    Elf64_Phdr *program_headers = malloc(header->e_phnum * sizeof(Elf64_Phdr));
    if (!program_headers) {
        perror("Failed to allocate memory for program headers");
        exit(EXIT_FAILURE);
    }
    lseek(fd, header->e_phoff, SEEK_SET);
    read(fd, program_headers, header->e_phnum * sizeof(Elf64_Phdr));

    // Read section headers
    Elf64_Shdr *section_headers = malloc(header->e_shnum * sizeof(Elf64_Shdr));
    if (!section_headers) {
        perror("Failed to allocate memory for section headers");
        free(program_headers);
        exit(EXIT_FAILURE);
    }
    lseek(fd, header->e_shoff, SEEK_SET);
    read(fd, section_headers, header->e_shnum * sizeof(Elf64_Shdr));

    // Read section names string table
    Elf64_Shdr sh_strtab = section_headers[header->e_shstrndx]; // Section header for section name string table
    char *section_names = malloc(sh_strtab.sh_size);
    if (!section_names) {
        perror("Failed to allocate memory for section names");
        free(program_headers);
        free(section_headers);
        exit(EXIT_FAILURE);
    }
    lseek(fd, sh_strtab.sh_offset, SEEK_SET);
    read(fd, section_names, sh_strtab.sh_size);

    // Print program headers (similar to previous function)
    printf("Program Headers:\n");
    printf("  Type           Offset             VirtAddr           PhysAddr\n");
    printf("                 FileSiz            MemSiz              Flags  Align\n");

    for (size_t i = 0; i < header->e_phnum; ++i) {
        char flags[4] = ""; // Buffer for flags
        get_flags(program_headers[i].p_flags, flags);

        // First line: Type, Offset, VirtAddr, PhysAddr
        printf("  %-14s 0x%016lx 0x%016lx 0x%016lx\n",
               get_segment_type_str(program_headers[i].p_type),
               program_headers[i].p_offset,
               program_headers[i].p_vaddr,
               program_headers[i].p_paddr);

        // Second line: FileSize, MemSize, Flags, Align
        printf("                 0x%016lx 0x%016lx  %-6s 0x%lx\n",
               program_headers[i].p_filesz,
               program_headers[i].p_memsz,
               flags,
               program_headers[i].p_align);
    }

    // Section to segment mapping
    printf("\n Section to Segment mapping:\n");
    printf("  Segment  Sections....\n");
    for (size_t i = 0; i < header->e_phnum; ++i) {
        printf("  %02zu       ", i);
        int found = 0; // Flag to track if any sections are mapped

        // Check each section if it falls under this segment
        for (size_t j = 0; j < header->e_shnum; ++j) {
            if (section_headers[j].sh_addr >= program_headers[i].p_vaddr &&
                section_headers[j].sh_addr < program_headers[i].p_vaddr + program_headers[i].p_memsz) {
                // Section belongs to this segment
                if (found) {
                    printf(" "); // Space between section names
                }
                printf("%s", &section_names[section_headers[j].sh_name]);
                found = 1;
            }
        }
        if (!found) {
            printf("None"); // If no sections are mapped
        }
        printf("\n");
    }

    // Clean up
    free(program_headers);
    free(section_headers);
    free(section_names);
}

const char *get_dynamic_tag_type(int64_t d_tag) {
    switch (d_tag) {
        case DT_NEEDED:     return "NEEDED";
        case DT_INIT:       return "INIT";
        case DT_FINI:       return "FINI";
        case DT_INIT_ARRAY: return "INIT_ARRAY";
        case DT_FINI_ARRAY: return "FINI_ARRAY";
        case DT_INIT_ARRAYSZ: return "INIT_ARRAYSZ";
        case DT_FINI_ARRAYSZ: return "FINI_ARRAYSZ";
        case DT_GNU_HASH:   return "GNU_HASH";
        case DT_STRTAB:     return "STRTAB";
        case DT_SYMTAB:     return "SYMTAB";
        case DT_STRSZ:      return "STRSZ";
        case DT_SYMENT:     return "SYMENT";
        case DT_DEBUG:      return "DEBUG";
        case DT_PLTGOT:     return "PLTGOT";
        case DT_PLTRELSZ:   return "PLTRELSZ";
        case DT_PLTREL:     return "PLTREL";
        case DT_JMPREL:     return "JMPREL";
        case DT_RELA:       return "RELA";
        case DT_RELASZ:     return "RELASZ";
        case DT_RELAENT:    return "RELAENT";
        case DT_FLAGS_1:    return "FLAGS_1";
        case DT_VERNEED:    return "VERNEED";
        case DT_VERNEEDNUM: return "VERNEEDNUM";
        case DT_VERSYM:     return "VERSYM";
        case DT_RELACOUNT:  return "RELACOUNT";
        case DT_NULL:       return "NULL";
        default:            return "UNKNOWN";
    }
}


// Function to print dynamic section
void print_dynamic_section(int fd, Elf64_Ehdr *header) {
    uint64_t dyn_offset = 0;
    uint64_t dyn_size = 0;

    // Read program headers
    Elf64_Phdr *program_headers = malloc(header->e_phnum * sizeof(Elf64_Phdr));
    if (!program_headers) {
        perror("Failed to allocate memory for program headers");
        close(fd);
        return;
    }
    lseek(fd, header->e_phoff, SEEK_SET);
    read(fd, program_headers, header->e_phnum * sizeof(Elf64_Phdr));

    // Find the PT_DYNAMIC segment
    for (size_t i = 0; i < header->e_phnum; ++i) {
        if (program_headers[i].p_type == PT_DYNAMIC) {
            dyn_offset = program_headers[i].p_offset;
            dyn_size = program_headers[i].p_filesz;
            break;
        }
    }

    if (dyn_offset == 0 || dyn_size == 0) {
        printf("No dynamic section found.\n");
        return;
    }

    // Read the dynamic section
    Elf64_Dyn *dynamic_entries = malloc(dyn_size);
    if (!dynamic_entries) {
        perror("Failed to allocate memory for dynamic section");
        exit(EXIT_FAILURE);
    }
    lseek(fd, dyn_offset, SEEK_SET);
    read(fd, dynamic_entries, dyn_size);

    printf("Dynamic section at offset 0x%lx contains %zu entries:\n", dyn_offset, dyn_size / sizeof(Elf64_Dyn));
    printf("  Tag        Type                         Name/Value\n");

    // Process dynamic entries
    for (size_t i = 0; dynamic_entries[i].d_tag != DT_NULL; ++i) {
        const char *tag_type = get_dynamic_tag_type(dynamic_entries[i].d_tag);
        printf("  0x%016lx %-28s ", dynamic_entries[i].d_tag, tag_type);

        // Special handling for certain tags
        if (dynamic_entries[i].d_tag == DT_NEEDED) {
            // If NEEDED, it's an index into the string table
            printf("Shared library: [%s]\n", "libc.so.6");  // For demo, replace with string table lookup
        } else {
            printf("0x%lx\n", dynamic_entries[i].d_un.d_val);
        }
    }

    free(dynamic_entries);
    free(program_headers);
}

const char* get_relocation_type(uint32_t r_type) {
    switch (r_type) {
        case R_X86_64_NONE: return "R_X86_64_NONE";
        case R_X86_64_64: return "R_X86_64_64";
        case R_X86_64_PC32: return "R_X86_64_PC32";
        case R_X86_64_GOT32: return "R_X86_64_GOT32";
        case R_X86_64_PLT32: return "R_X86_64_PLT32";
        case R_X86_64_COPY: return "R_X86_64_COPY";
        case R_X86_64_GLOB_DAT: return "R_X86_64_GLOB_DAT";
        case R_X86_64_JUMP_SLOT: return "R_X86_64_JUMP_SLOT";
        case R_X86_64_RELATIVE: return "R_X86_64_RELATIVE";
        case R_X86_64_GOTPCREL: return "R_X86_64_GOTPCREL";
        default: return "Unknown";
    }
}

void print_relocation_section(int fd, Elf64_Ehdr *header) {
    // Read section headers
    Elf64_Shdr *section_headers = malloc(header->e_shnum * sizeof(Elf64_Shdr));
    if (!section_headers) {
        perror("Failed to allocate memory for section headers");
        close(fd);
        return;
    }

    // Read the section headers
    lseek(fd, header->e_shoff, SEEK_SET);
    read(fd, section_headers, header->e_shnum * sizeof(Elf64_Shdr));

    // Read section header string table
    char *section_string_table = malloc(section_headers[header->e_shstrndx].sh_size);
    if (!section_string_table) {
        perror("Failed to allocate memory for section string table");
        free(section_headers);
        close(fd);
        return;
    }

    lseek(fd, section_headers[header->e_shstrndx].sh_offset, SEEK_SET);
    read(fd, section_string_table, section_headers[header->e_shstrndx].sh_size);


    // Iterate through section headers to find relocation sections
    for (size_t i = 0; i < header->e_shnum; ++i) {
        // Check for the '.rela.dyn' section by name
        if (section_headers[i].sh_type == SHT_RELA) {
            
            const char *section_name = &section_string_table[section_headers[i].sh_name];

            printf("Relocation section '%s' at offset 0x%lx contains %lu entries:\n",
                   section_name,
                   section_headers[i].sh_offset,
                   section_headers[i].sh_size / sizeof(Elf64_Rela));

            // Allocate memory for relocation entries
            Elf64_Rela *relocation_entries = malloc(section_headers[i].sh_size);
            if (!relocation_entries) {
                perror("Failed to allocate memory for relocation entries");
                free(section_headers);
                close(fd);
                return;
            }

            // Read relocation entries
            lseek(fd, section_headers[i].sh_offset, SEEK_SET);
            read(fd, relocation_entries, section_headers[i].sh_size);

            // Print relocation entries
            printf("  Offset            Info              Type               Sym. Value          Sym. Name + Addend\n");
            for (size_t j = 0; j < section_headers[i].sh_size / sizeof(Elf64_Rela); ++j) {
                uint32_t r_type = ELF64_R_TYPE(relocation_entries[j].r_info);
                uint32_t r_sym = ELF64_R_SYM(relocation_entries[j].r_info);

                printf("  %016lx  %016lx  ", relocation_entries[j].r_offset, relocation_entries[j].r_info);
                printf("%-15s  ", get_relocation_type(r_type));
                printf("0x%016lx  ", relocation_entries[j].r_addend);  // Addend
                printf("Symbol %u\n", r_sym); // Placeholder for actual symbol name resolution
            }

            free(relocation_entries);
        }
    }

    // Clean up
    free(section_headers);
}


// Helper function to get the symbol type as a string
const char *get_symbol_type(uint8_t st_info) {
    uint8_t type = ELF64_ST_TYPE(st_info);
    switch (type) {
        case STT_NOTYPE: return "NOTYPE";
        case STT_OBJECT: return "OBJECT";
        case STT_FUNC:   return "FUNC";
        case STT_SECTION: return "SECTION";
        case STT_FILE: return "FILE";
        case STT_TLS: return "TLS";
        default: return "UNKNOWN";
    }
}

// Helper function to get the symbol binding as a string
const char *get_symbol_bind(uint8_t st_info) {
    uint8_t bind = ELF64_ST_BIND(st_info);
    switch (bind) {
        case STB_LOCAL:  return "LOCAL";
        case STB_GLOBAL: return "GLOBAL";
        case STB_WEAK:   return "WEAK";
        case STB_NUM:    return "NUM";
        case STB_LOOS:   return "LOOS";
        case STB_HIOS:   return "HIOS";
        case STB_LOPROC: return "LOPROC";
        case STB_HIPROC: return "HIPROC";
        default: return "UNKNOWN";
    }
}

// Helper function to get the visibility as a string
const char *get_symbol_visibility(uint8_t st_other) {
    uint8_t visibility = ELF64_ST_VISIBILITY(st_other);
    switch (visibility) {
        case STV_DEFAULT: return "DEFAULT";
        case STV_INTERNAL: return "INTERNAL";
        case STV_HIDDEN: return "HIDDEN";
        case STV_PROTECTED: return "PROTECTED";
        default: return "UNKNOWN";
    }
}

// Helper function to get the section index
const char *get_section_index(uint16_t shndx) {
    switch (shndx) {
        case SHN_UNDEF: return "UND";
        case SHN_ABS: return "ABS";
        case SHN_COMMON: return "COM";
        default: return "N/A"; // You can implement more if needed
    }
}

// Helper function to get the symbol name
const char *get_symbol_name(Elf64_Shdr *section_headers, Elf64_Sym *symbol_entries, size_t index, char *section_string_table) {
    return &section_string_table[symbol_entries[index].st_name];
}

void print_symbol_table(int fd, Elf64_Ehdr *header) {
    // Read section headers
    Elf64_Shdr *section_headers = malloc(header->e_shnum * sizeof(Elf64_Shdr));
    if (!section_headers) {
        perror("Failed to allocate memory for section headers");
        close(fd);
        return;
    }

    lseek(fd, header->e_shoff, SEEK_SET);
    read(fd, section_headers, header->e_shnum * sizeof(Elf64_Shdr));

    // Read section header string table
    char *section_string_table = malloc(section_headers[header->e_shstrndx].sh_size);
    if (!section_string_table) {
        perror("Failed to allocate memory for section string table");
        free(section_headers);
        close(fd);
        return;
    }

    lseek(fd, section_headers[header->e_shstrndx].sh_offset, SEEK_SET);
    read(fd, section_string_table, section_headers[header->e_shstrndx].sh_size);

    // Iterate over section headers to find symbol tables
    for (size_t i = 0; i < header->e_shnum; ++i) {
        const char *section_name = &section_string_table[section_headers[i].sh_name];

        if (section_headers[i].sh_type == SHT_SYMTAB || section_headers[i].sh_type == SHT_DYNSYM) {
            // Print the symbol table header
            printf("Symbol table '%s' contains %lu entries:\n", section_name,
                   section_headers[i].sh_size / sizeof(Elf64_Sym));

            // Read symbol entries
            Elf64_Sym *symbol_entries = malloc(section_headers[i].sh_size);
            if (!symbol_entries) {
                perror("Failed to allocate memory for symbol entries");
                free(section_string_table);
                free(section_headers);
                close(fd);
                return;
            }

            lseek(fd, section_headers[i].sh_offset, SEEK_SET);
            read(fd, symbol_entries, section_headers[i].sh_size);

            // Print symbol entries
            printf("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n");
            for (size_t j = 0; j < section_headers[i].sh_size / sizeof(Elf64_Sym); ++j) {
                Elf64_Sym *sym = &symbol_entries[j];

                // Print symbol attributes
                printf("    %lu:  %016lx %5lu ", j, sym->st_value, sym->st_size);
                printf("%-7s %-6s %-8s ", get_symbol_type(sym->st_info), get_symbol_bind(sym->st_info), get_symbol_visibility(sym->st_other));
                printf("%-5s %s\n", get_section_index(sym->st_shndx), get_symbol_name(section_headers, symbol_entries, j, section_string_table));
            }

            free(symbol_entries);
        }
    }

    // Clean up
    free(section_string_table);
    free(section_headers);
}




int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    Elf64_Ehdr header;
    if (read(fd, &header, sizeof(header)) != sizeof(header)) {
        perror("Error reading ELF header");
        close(fd);
        return EXIT_FAILURE;
    }

    // Print ELF header
    print_elf_header(&header);

    // Print section headers
    print_section_headers(fd, &header);

    // Print program headers
    print_program_headers(fd, &header);

    print_dynamic_section(fd, &header);

    print_relocation_section(fd, &header);

    print_symbol_table(fd, &header);

    close(fd);
    return EXIT_SUCCESS;
}
