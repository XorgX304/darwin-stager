//
//  main.m
//  flatten-macho
//
//  Created by qwertyoruiop on 4/6/17.
//  Copyright © 2017 qwertyoruiop. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <fcntl.h>
#import <unistd.h>
#import <sys/stat.h>
#import <sys/mman.h>

int main(int argc, const char * argv[]) {
  if(argc != 3)
  {
    printf("usage: %s <input> <output>\n", argv[0]);
    return -1;
  }
  int fd = open(argv[1], O_RDONLY);
  int fd_w = open(argv[2], O_RDWR|O_CREAT|O_TRUNC, 0755);

  char header[0x4000];
  pread(fd, header, 0x4000, 0);

  struct mach_header* mh = header;
  uint64_t min = -1;
  uint64_t max = 0;
  struct load_command* lc = mh+1;
  for (int i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT)
    {
      struct segment_command* sg = lc;
      if (strcmp(sg->segname, "__PAGEZERO") != 0) {
        printf("segment %s\n", sg->segname);
        if (sg->vmaddr < min) min = sg->vmaddr;
        if (sg->vmaddr+sg->vmsize > max) max = sg->vmaddr+sg->vmsize;
      }
    }
    lc = (((char*)lc)+lc->cmdsize);
  }

  printf("found base: %llx, max: %llx\n", min, max);
  if(lseek(fd_w, max, SEEK_SET) == -1)
  {
    printf("seek failed\n");
    return -1;
  }

  lc = mh+1;
  for (int i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_SEGMENT)
    {
      struct segment_command* sg = lc;
      printf("mapping to %llx %llx %llx\n", sg->vmaddr, sg->fileoff, sg->filesize);

      if (sg->filesize == 0) {
        lc = (((char*)lc)+lc->cmdsize);
        continue;
      } // ignore pagezero
      char* map = mmap(0, sg->vmsize, PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0);
      if(mmap(map, sg->filesize, PROT_READ, MAP_FIXED|MAP_FILE|MAP_PRIVATE,fd,sg->fileoff) == MAP_FAILED)
      {
        printf("mmap failed\n");
        return -1;
      }
      printf("seeking to %llx\n", sg->vmaddr-min);
      lseek(fd_w, sg->vmaddr-min, SEEK_SET);
      write(fd_w, map, sg->vmsize);
      munmap(map, sg->vmsize);
    }
    lc = (((char*)lc)+lc->cmdsize);
  }

  return 0;
}

