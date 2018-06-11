/*
 * References:
 * @parchedmind
 * https://github.com/CylanceVulnResearch/osx_runbin/blob/master/run_bin.c
 *
 * @nologic
 * https://github.com/nologic/shellcc
 */

#include <stdio.h>
#include <string.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <dlfcn.h>
#include <asl.h>

#include <sys/types.h>
#include <sys/sysctl.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_T LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_T LC_SEGMENT
#endif

struct dyld_cache_header
{
    char        magic[16];        // e.g. "dyld_v0     ppc"
    uint32_t    mappingOffset;    // file offset to first shared_file_mapping
    uint32_t    mappingCount;     // number of shared_file_mapping entries
    uint32_t    imagesOffset;     // file offset to first dyld_cache_image_info
    uint32_t    imagesCount;      // number of dyld_cache_image_info entries
    uint64_t    dyldBaseAddress;  // base address of dyld when cache was built
		uint64_t    codeSignatureOffset;
		uint64_t    codeSignatureSize;
		uint64_t    slideInfoOffset;
		uint64_t    slideInfoSize;
		uint64_t    localSymbolsOffset;
		uint64_t    localSymbolsSize;
		char        uuid[16];
};

struct shared_file_mapping {
    uint64_t       address;
    uint64_t       size;
    uint64_t       file_offset;
    uint32_t       max_prot;
    uint32_t       init_prot;
};

struct dyld_cache_image_info
{
    uint64_t    address;
    uint64_t    modTime;
    uint64_t    inode;
    uint32_t    pathFileOffset;
    uint32_t    pad;
};

long syscall(const long syscall_number, const long arg1, const long arg2, const long arg3, const long arg4, const long arg5, const long arg6);
int main(int argc, char** argv);
void * get_dyld_function(const char* function_symbol);
uint64_t syscall_chmod(uint64_t path, long mode);
uint64_t syscall_shared_region_check_np();

uint32_t syscall_write(uint32_t fd, const char* buf, uint32_t size);
void init();

int main(int argc, char** argv)
{
  init();
  return 0;
}

void init()
{
  /*printf("syscall_write\n");*/
  /*syscall_write(1, "lal\n", 4);*/
  /*printf("syscall_write done\n");*/

  /*uint64_t shared_region_check = syscall_shared_region_check_np();*/
  /*printf("shared %p\n", shared_region_check);*/
  /*uint64_t dllookup_func = (uint64_t)get_dlsym_addr();*/
  uint64_t dlsym_addr = (uint64_t)get_dyld_function("_dlsym");
  printf("dlsym %p\n", dlsym_addr);
  uint64_t dlopen_addr = (uint64_t)get_dyld_function("_dlopen");
  printf("dlopen %p\n", dlopen_addr);
  /*struct dyld_cache_header *header = (void*)shared_region_start;*/
  /*struct shared_file_mapping *sfm = (void*)header + header->mappingOffset;*/
  /*void* vm_slide_offset  = (void*)header - sfm->address;*/
  /*NSLog(@"vm_slide_offset %p\n",  vm_slide_offset);*/

  /*struct dyld_cache_image_info *dcimg = (void*)header + header->imagesOffset;*/
  /*void * libdyld_address;*/
  /*for (size_t i=0; i < header->imagesCount; i++) {*/
    /*char * pathFile = (char *)shared_region_start+dcimg->pathFileOffset;*/
    /*if (strstr(pathFile, "libdyld.dylib") != -0) {*/
      /*libdyld_address = (dcimg->address + vm_slide_offset);*/
      /*break;*/
    /*}*/
    /*dcimg++;*/
  /*}*/

  typedef void* (*dlsym_ptr)(void *handle, const char *symbol);
  typedef void* (*dlopen_ptr)(const char *filename, int flags);
  typedef int (*asl_log_ptr)(aslclient asl, aslmsg msg, int level, const char *format, ...);
  dlsym_ptr dlsym_func = dlsym_addr;
  dlopen_ptr dlopen_func = dlopen_addr;
  void* libsystem = dlopen_func("/usr/lib/libSystem.B.dylib", RTLD_NOW);
  asl_log_ptr asl_log_func = dlsym_func(libsystem, "asl_log");
  asl_log_func(0, 0, ASL_LEVEL_ERR, "hello from metasploit!\n");

  typedef int (*printf_ptr)(const char *format, ...);
  printf_ptr printf_func = dlsym_func(libsystem, "printf");
  printf_func("Hello world\n");
  /*printf_global = printf_func;*/
  /*printf_func("start %p\n", get_dyld_function("start"));*/
  /*printf_func("_start %p\n", get_dyld_function("_start"));*/

  /*print_dyld_function(printf_func);*/

  /*uint64_t binary = find_macho(0x120000000, 0x1000, 0);*/
  /*printf_func("binary %p\n", (void*)binary);*/
  /*uint64_t dyld = find_macho(binary + 0x1000, 0x1000, 0);*/
  /*printf_func("dyld %p\n", (void*)dyld);*/
  /*printf_func("shared %p\n", (void*)shared_region_check);*/
  return;

  typedef void (*func_ptr)();
  func_ptr func = (func_ptr)0x4545454545;
/*#ifdef __x86_64*/
#ifdef __aarch64__
	volatile register uint64_t x0 asm("x0") = 0x45454541;
	volatile register uint64_t x1 asm("x1") = (uint64_t)dlsym_func;
	volatile register uint64_t x2 asm("x2") = (uint64_t)libsystem;
	volatile register uint64_t x3 asm("x3") = (uint64_t)asl_log_func;
	volatile register uint64_t x4 asm("x4") = (uint64_t)0x79;
  asm volatile (
      "mov x0, %0\n\t"
      "mov x1, %1\n\t"
      "mov x2, %2\n\t"
      "mov x3, %3\n\t"
      "mov x4, %4\n\t"
      :
      : "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
      : "x0", "x1", "x2", "x3", "x4");
#endif
  func();
}


uint32_t syscall_write(uint32_t fd, const char* buf, uint32_t size)
{
  return syscall(4, fd, buf, size, 0, 0, 0);
}

uint64_t syscall_chmod(uint64_t path, long mode)
{
  return syscall(15, path, mode, 0, 0, 0, 0);
}

uint64_t syscall_shared_region_check_np()
{
  uint64_t address = 0;
  syscall(294, &address, 0, 0, 0, 0, 0);
  return address;
}

long syscall(const long syscall_number, const long arg1, const long arg2, const long arg3, const long arg4, const long arg5, const long arg6){
  long ret;
#ifdef __x86_64
  asm volatile (
      "movq %1, %%rax\n\t"
      "movq %2, %%rdi\n\t"
      "movq %3, %%rsi\n\t"
      "movq %4, %%rdx\n\t"
      "movq %5, %%rcx\n\t"
      "movq %6, %%r8\n\t"
      "movq %7, %%r9\n\t"
      "syscall"
      : "=a"(ret)
      : "g"(syscall_number), "g"(arg1), "g"(arg2), "g"(arg3), "g"(arg4), "g"(arg5), "g"(arg6)    );
#elif __arm__
  /*write(1, arg2, 4);*/
  /*asm volatile (*/
      /*"mov r0, 1\n"*/
      /*"mov r1, %1\n"*/
      /*"mov r2, 4\n"*/
      /*"mov r12, #4\n"*/
      /*"swi 0x80\n"*/
      /*"mov %0, r0\n"*/
      /*: "=r"(ret)*/
      /*: "r"(arg2)*/
      /*: "r0", "r1", "r2", "r12");*/
  volatile register uint32_t r12 asm("r12") = syscall_number;
  volatile register uint32_t r0 asm("r0") = arg1;
  volatile register uint32_t r1 asm("r1") = arg2;
  volatile register uint32_t r2 asm("r2") = arg3;
  volatile register uint32_t r3 asm("r3") = arg4;
  volatile register uint32_t r4 asm("r4") = arg5;
  volatile register uint32_t r5 asm("r5") = arg6;
  volatile register uint32_t xret asm("r0");
  asm volatile (
      "mov r0, %2\n"
      "mov r1, %3\n"
      "mov r2, %4\n"
      "mov r3, %5\n"
      "mov r4, %6\n"
      "mov r5, %7\n"
      "mov r12, %1\n"
      "swi 0x80\n"
      "mov %0, r0\n"
      : "=r"(xret)
      : "r"(r12), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
      : "r0", "r1", "r2", "r3", "r4", "r5", "r12");
  ret = xret;
#elif __aarch64__
  // : ¯\_(ツ)_/¯
	volatile register uint64_t x16 asm("x16") = syscall_number;
	volatile register uint64_t x0 asm("x0") = arg1;
	volatile register uint64_t x1 asm("x1") = arg2;
	volatile register uint64_t x2 asm("x2") = arg3;
	volatile register uint64_t x3 asm("x3") = arg4;
	volatile register uint64_t x4 asm("x4") = arg5;
	volatile register uint64_t x5 asm("x5") = arg6;
	volatile register uint64_t xret asm("x0");
  asm volatile (
      "mov x0, %2\n\t"
      "mov x1, %3\n\t"
      "mov x2, %4\n\t"
      "mov x3, %5\n\t"
      "mov x4, %6\n\t"
      "mov x5, %7\n\t"
      "mov x16, %1\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      : "=r"(xret)
      /*: "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6)*/
      : "r"(x16), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
      : "x0", "x1", "x2", "x3", "x4", "x5", "x16");
  ret = xret;
#endif
  return ret;
}

int string_compare(const char* s1, const char* s2) 
{
  while (*s1 != '\0' && *s1 == *s2)
  {
    s1++;
    s2++;
  }
  return (*(unsigned char *) s1) - (*(unsigned char *) s2);
}

void * get_dyld_function(const char* function_symbol) 
{
  uint64_t shared_region_start = syscall_shared_region_check_np();

  struct dyld_cache_header *header = (void*)shared_region_start;
  /*printf("symbol %p\n", header);*/
  struct shared_file_mapping *sfm = (void*)header + header->mappingOffset;
  struct dyld_cache_image_info *dcimg = (void*)header + header->imagesOffset;
  uint64_t libdyld_address;
  for (size_t i=0; i < header->imagesCount; i++) {
    char * pathFile = (char *)shared_region_start+dcimg->pathFileOffset;
    //NSLog(@"pathFile %p %s\n", (void*)dcimg->address, pathFile);
    if (string_compare(pathFile, "/usr/lib/system/libdyld.dylib") == 0) {
      //NSLog(@"dyld_address %p\n",  dcimg->address);
      libdyld_address = dcimg->address;
      break;
    }
    dcimg++;
  }
  void* vm_slide_offset  = (void*)header - sfm->address;
  //NSLog(@"vm_slide_offset %p\n",  vm_slide_offset);
  libdyld_address = (libdyld_address + vm_slide_offset);

  mach_header_t *mh = (mach_header_t*)libdyld_address;
  const struct load_command* cmd = (struct load_command*)(((char*)mh)+sizeof(mach_header_t));
  struct symtab_command* symtab_cmd = 0;
  segment_command_t* linkedit_cmd = 0;
  segment_command_t* text_cmd = 0;

  for (uint32_t i = 0; i < mh->ncmds; ++i) {
    //NSLog(@"line %d load %p %p", __LINE__, cmd->cmd, cmd);
    if (cmd->cmd == LC_SEGMENT_T) {
      segment_command_t* segment_cmd = (struct segment_command_t*)cmd;
      if (string_compare(segment_cmd->segname, SEG_TEXT) == 0) {
        text_cmd = segment_cmd;
        /*NSLog(@"text_segment :%p %s %p %p %p %p:\n", segment_cmd, segment_cmd->segname, segment_cmd->vmaddr, segment_cmd->fileoff, segment_cmd->nsects, segment_cmd->cmd);*/
      } else if (string_compare(segment_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_cmd = segment_cmd;
        /*NSLog(@"linkedit :%p %p vmaddr %p fileoff %p:\n", linkedit_cmd, segment_cmd->segname, linkedit_cmd->vmaddr, linkedit_cmd->fileoff);*/
      }
    }
    if (cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cmd;
      /*NSLog(@"symtab :%p %d %p %p %p:\n", symtab_cmd, symtab_cmd->nsyms, symtab_cmd->symoff, symtab_cmd->stroff, symtab_cmd->strsize);*/
    }
    cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
  }

  unsigned int file_slide = ((unsigned long)linkedit_cmd->vmaddr - (unsigned long)text_cmd->vmaddr) - linkedit_cmd->fileoff;
  nlist_t *sym = (nlist_t*)((unsigned long)mh + (symtab_cmd->symoff + file_slide));
  char *strings = (char*)((unsigned long)mh + (symtab_cmd->stroff + file_slide));

  for (uint32_t i = 0; i < symtab_cmd->nsyms; ++i) {
    if (sym->n_un.n_strx) {
      char * symbol = strings + sym->n_un.n_strx;
      /*printf("symbol %s\n", symbol);*/
      if (function_symbol == 0) {
      /*NSLog(@"symbol :%s %p:\n", symbol, sym->n_value);*/
        /*printf_global("Symbol %s\n", symbol);*/
      }
      if (string_compare(symbol, function_symbol) == 0) {
        return sym->n_value + vm_slide_offset;
      }
    }
    sym += 1;
  }
  return 0;
}


