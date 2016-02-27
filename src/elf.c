/*
 * Copyright (c) 2013-2016 Tom Rix
 * All rights reserved.
 *
 * You may distribute under the terms of :
 *
 * the BSD 2-Clause license
 *
 * Any patches released for this software are to be released under these
 * same license terms.
 *
 * BSD 2-Clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * Forward decl of os parts
 * Do not want to mix os's Elf types with ours
 */
int elf_os_image(pid_t pid);

/* Globals */
extern FILE *fp_log;

/* 32 bit */
typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef uint32_t Elf32_Word;
/* 64 bit */
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;

#define EI_CLASS      4
#define EI_NIDENT    16

#define ELFCLASS32 1
#define ELFCLASS64 2

#define ELF_SECTION_NAME_SYMTAB        ".symtab"
#define ELF_SECTION_NAME_STRTAB        ".strtab"

#define IS64(h) (((h)->e_ident[EI_CLASS] == ELFCLASS64) ? true : false)

typedef struct {
  unsigned char e_ident[EI_NIDENT];
  union {
    struct {
      Elf32_Half e_type;
      Elf32_Half e_machine;
      Elf32_Word e_version;
      Elf32_Addr e_entry;
      Elf32_Off e_phoff;
      Elf32_Off e_shoff;
      Elf32_Word e_flags;
      Elf32_Half e_ehsize;
      Elf32_Half e_phentsize;
      Elf32_Half e_phnum;
      Elf32_Half e_shentsize;
      Elf32_Half e_shnum;
      Elf32_Half e_shstrndx;
    } e32;
    struct {
      Elf64_Half e_type;
      Elf64_Half e_machine;
      Elf64_Word e_version;
      Elf64_Addr e_entry;
      Elf64_Off e_phoff;
      Elf64_Off e_shoff;
      Elf64_Word e_flags;
      Elf64_Half e_ehsize;
      Elf64_Half e_phentsize;
      Elf64_Half e_phnum;
      Elf64_Half e_shentsize;
      Elf64_Half e_shnum;
      Elf64_Half e_shstrndx;
    } e64;
  } u;
} elf_file_header;

typedef struct {
  union {
    struct {
      Elf32_Word sh_name;
      Elf32_Word sh_type;
      Elf32_Word sh_flags;
      Elf32_Addr sh_addr;
      Elf32_Off sh_offset;
      Elf32_Word sh_size;
      Elf32_Word sh_link;
      Elf32_Word sh_info;
      Elf32_Word sh_addralign;
      Elf32_Word sh_entsize;
    } e32;
    struct {
      Elf64_Word sh_name;
      Elf64_Word sh_type;
      Elf64_Xword sh_flags;
      Elf64_Addr sh_addr;
      Elf64_Off sh_offset;
      Elf64_Xword sh_size;
      Elf64_Word sh_link;
      Elf64_Word sh_info;
      Elf64_Xword sh_addralign;
      Elf64_Xword sh_entsize;
    } e64;
  } u;
} elf_section_header;

typedef struct {
  union {
    struct {
      Elf32_Word st_name;    
      Elf32_Addr st_value;   
      Elf32_Word st_size;    
      unsigned char st_info; 
      unsigned char st_other;
      Elf32_Half st_shndx;
    } e32;
    struct {
      Elf64_Word st_name;
      unsigned char st_info;
      unsigned char st_other;
      Elf64_Half st_shndx;
      Elf64_Addr st_value;
      Elf64_Xword st_size;
    } e64;
  } u;
} elf_symbol;

static void *elf_mmap(int fd) {
  void *mm = NULL;
  struct stat sb;
  if (fstat(fd, &sb) == 0) {
    if (sb.st_size > 0) {
      mm = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    }
  }
  return mm;
}

static void elf_munmap(int fd, void *mm) {
  struct stat sb;
  if (fstat(fd, &sb)) {
    if ((sb.st_size > 0) && (mm != NULL)) {
      munmap(mm, sb.st_size);
    }
  }
}

static char *elf_shstring_table32(void *mm) {
  elf_file_header *efh = (elf_file_header *)mm;
  size_t shoff = efh->u.e32.e_shoff;
  size_t shstrndx = efh->u.e32.e_shstrndx;
  size_t shentsize = efh->u.e32.e_shentsize;
  elf_section_header *esh = (elf_section_header *) (mm + shoff + (shstrndx * shentsize));
  return (mm + esh->u.e32.sh_offset);
}

static char *elf_shstring_table64(void *mm) {
  elf_file_header *efh = (elf_file_header *)mm;
  size_t shoff = efh->u.e64.e_shoff;
  size_t shstrndx = efh->u.e64.e_shstrndx;
  size_t shentsize = efh->u.e64.e_shentsize;
  elf_section_header *esh = (elf_section_header *) (mm + shoff + (shstrndx * shentsize));
  return (mm + esh->u.e64.sh_offset);
}

static elf_section_header *elf_find_section32(void *mm, char *name)
{
  elf_file_header *efh = (elf_file_header *)mm;
  char *string_table = elf_shstring_table32(mm);
  size_t shoff = efh->u.e32.e_shoff;
  size_t shnum = efh->u.e32.e_shnum;
  size_t shentsize = efh->u.e32.e_shentsize;
  size_t idx;
  for (idx = 0; idx < shnum; idx++) {
    size_t offset = shoff + (idx * shentsize);
    elf_section_header *esh = (elf_section_header *) (mm + offset);
    size_t str_off = esh->u.e32.sh_name;
    char *try_name = &string_table[str_off];
    if ((strlen(try_name) == strlen(name)) &&
	(strcmp(try_name, name) == 0)) {
      return esh;
    }
  }
  return NULL;
}

static elf_section_header *elf_find_section64(void *mm, char *name)
{
  elf_file_header *efh = (elf_file_header *)mm;
  char *string_table = elf_shstring_table64(mm);
  size_t shoff = efh->u.e64.e_shoff;
  size_t shnum = efh->u.e64.e_shnum;
  size_t shentsize = efh->u.e64.e_shentsize;
  size_t idx;
  for (idx = 0; idx < shnum; idx++) {
    size_t offset = shoff + (idx * shentsize);
    elf_section_header *esh = (elf_section_header *) (mm + offset);
    size_t str_off = esh->u.e64.sh_name;
    char *try_name = &string_table[str_off];
    if ((strlen(try_name) == strlen(name)) &&
	(strcmp(try_name, name) == 0)) {
      return esh;
    }
  }
  return NULL;
}

static char *elf_string_table32(void *mm) {
  char *ret = NULL;
  elf_section_header *esh = elf_find_section32(mm, ELF_SECTION_NAME_STRTAB);
  if (esh) {
    ret = mm + esh->u.e32.sh_offset;
  }
  return (ret);
}

static char *elf_string_table64(void *mm) {
  char *ret = NULL;
  elf_section_header *esh = elf_find_section64(mm, ELF_SECTION_NAME_STRTAB);
  if (esh) {
    ret = mm + esh->u.e64.sh_offset;
  }
  return (ret);
}

static void * elf_section32(void *mm, elf_section_header *esh) {
  return (mm + esh->u.e32.sh_offset);
}

static void * elf_section64(void *mm, elf_section_header *esh) {
  return (mm + esh->u.e64.sh_offset);
}

static void elf_dump_symbol_table32(void *mm) {
  elf_section_header *esh;
  esh = elf_find_section32(mm, ELF_SECTION_NAME_SYMTAB);
  char *string_table = elf_string_table32(mm);
  if (esh && string_table) {
    void *sec = (elf_symbol *) elf_section32(mm, esh);
    size_t size_sym = esh->u.e32.sh_entsize;
    size_t number_sym = esh->u.e32.sh_size / size_sym;
    size_t idx;
    fprintf(stderr, "Symbol table size %zu\n", number_sym);
    for (idx = 0; idx < number_sym; idx++) {
      elf_symbol *sym = (elf_symbol *) (sec + (idx * size_sym));
      size_t str_off = sym->u.e32.st_name;
      uint32_t addr  = sym->u.e32.st_value;
      char *name = &string_table[str_off];
      fprintf(stderr, "%zu : %08" PRIx32 " %s\n",
	      idx, addr, (str_off != 0) ? name : "");
    }
  }
}

static void elf_dump_symbol_table64(void *mm) {
  elf_section_header *esh;
  esh = elf_find_section64(mm, ELF_SECTION_NAME_SYMTAB);
  char *string_table = elf_string_table64(mm);
  if (esh && string_table) {
    void *sec = (elf_symbol *) elf_section64(mm, esh);
    size_t size_sym = esh->u.e64.sh_entsize;
    size_t number_sym = esh->u.e64.sh_size / size_sym;
    size_t idx;
    fprintf(stderr, "Symbol table size %zu\n", number_sym);
    for (idx = 0; idx < number_sym; idx++) {
      elf_symbol *sym = (elf_symbol *) (sec + (idx * size_sym));
      size_t str_off = sym->u.e64.st_name;
      uint64_t addr  = sym->u.e64.st_value;
      char *name = &string_table[str_off];
      fprintf(stderr, "%zu : %016" PRIx64 " %s\n",
	      idx, addr, (str_off != 0) ? name : "");
    }
  }
}
void elf_dump_symbol_table(pid_t pid) {
  if (fp_log) {
    int fd = elf_os_image(pid);
    if (fd >= 0) {
      void *mm = elf_mmap(fd);
      if (mm) {
	elf_file_header *efh = (elf_file_header *)mm;
	if (IS64(efh))
	  elf_dump_symbol_table64(mm);
	else
	  elf_dump_symbol_table32(mm);
	elf_munmap(fd, mm);
      }
      close(fd);
    }
  }
}
