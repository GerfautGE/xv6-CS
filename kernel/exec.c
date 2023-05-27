#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"

static int loadseg(pde_t *pgdir, uint64 addr, struct inode *ip, uint offset, uint sz);



int
exec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz, sp, ustack[MAXARG+1], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  //VMAs to save
  struct vma* stack_vma = p->stack_vma;
  struct vma* heap_vma = p->heap_vma;
  struct vma* memory_areas = p->memory_areas;

  begin_op(ROOTDEV);
  int max_addr = max_addr_in_memory_areas(p);
  if((ip = namei(path)) == 0){
    end_op(ROOTDEV);
    return -1;
  }
  ilock(ip);

  // Check ELF header
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf)){
    printf("exec: readi error\n");
    goto bad;
  }
  if(elf.magic != ELF_MAGIC){
    printf("exec: bad number error\n");
    goto bad;
  }
  if((pagetable = proc_pagetable(p)) == 0){
    printf("exec: proc_pagetable error\n");
    goto bad;
  }

  //reset VMAs
  acquire(&p->vma_lock);
  p->memory_areas = 0;
  p->stack_vma = 0;
  p->heap_vma = 0;
  release(&p->vma_lock);

  // Load program into memory.
  sz = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph)){
      printf("exec: program header error\n");
    }
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz){
      printf("exec: program header memsz < filesz\n");
      goto bad;
    }
    if(ph.vaddr + ph.memsz < ph.vaddr){
      printf("exec: program header vaddr + memsz < vaddr\n");
      goto bad;
    }
    if((sz = uvmalloc(pagetable, sz, ph.vaddr + ph.memsz)) == 0){
      printf("exec: uvmalloc failed\n");
      goto bad;
    }
    if(ph.vaddr % PGSIZE != 0){
      printf("exec: vaddr not page aligned\n");
      goto bad;
    }
    add_memory_area(p, PGROUNDUP(ph.vaddr), PGROUNDUP(ph.vaddr + ph.memsz))->vma_flags = VMA_R | VMA_W | VMA_X;
    if(loadseg(pagetable, ph.vaddr, ip, ph.off, ph.filesz) < 0){
      printf("exec: loadseg failed\n");
      goto bad;
    }
  }
  iunlockput(ip);
  end_op(ROOTDEV);
  ip = 0;

  p = myproc();

  // Allocate two pages at the next page boundary.
  // Use the second as the user stack.
  sz = PGROUNDUP(sz);
  p->stack_vma = add_memory_area(p, USTACK_BOTTOM, USTACK_TOP);
  p->stack_vma->vma_flags = VMA_R | VMA_W;
  sz = USTACK_TOP;
  sp = sz;
  stackbase = sp - PGSIZE;
  p->heap_vma =  add_memory_area(p, sz, sz); //heap
  p->heap_vma->vma_flags = VMA_R | VMA_W; 
  
  // Push argument strings, prepare rest of stack in ustack.
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG){
      printf("exec: too many args\n");
      goto bad;
    }
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase){
      printf("exec: sp < stackbase\n");
      goto bad;
    }
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0){
      printf("exec: copy argument strings failed\n");
      goto bad;
    }
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase){
    printf("exec: sp < stackbase, le retour\n");
    goto bad;
  }
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0){
    printf("exec: copy argument pointers failed\n");
    goto bad;
  }

  // arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->tf->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));

  if(p->cmd) bd_free(p->cmd);
  p->cmd = strjoin(argv);

  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->tf->epc = elf.entry;  // initial program counter = main
  p->tf->sp = sp; // initial stack pointer
  proc_freepagetable(oldpagetable, max_addr);
  free_vma(memory_areas);
  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, max_addr);
  if(ip){
    iunlockput(ip);
    end_op(ROOTDEV);
  }
  acquire(&p->vma_lock);
  p->memory_areas = memory_areas;
  p->stack_vma = stack_vma;
  p->heap_vma = heap_vma;
  release(&p->vma_lock);
  return -1;
}

// Load a program segment into pagetable at virtual address va.
// va must be page-aligned
// and the pages from va to va+sz must already be mapped.
// Returns 0 on success, -1 on failure.
static int
loadseg(pagetable_t pagetable, uint64 va, struct inode *ip, uint offset, uint sz)
{
  uint i, n;
  uint64 pa;

  if((va % PGSIZE) != 0)
    panic("loadseg: va must be page aligned");

  for(i = 0; i < sz; i += PGSIZE){
    pa = walkaddr(pagetable, va + i);
    if(pa == 0)
      panic("loadseg: address should exist");
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, 0, (uint64)pa, offset+i, n) != n)
      return -1;
  }
  
  return 0;
}
