#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "mmap.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

int
check_guard_page(struct map_mem *m, uint fault_addr)
{
  struct proc *curproc = myproc();
  int i;

  for(i = 0; i < MAX_MAPS; i++) {
    struct map_mem *guard = &curproc->map[i];
    if(!guard->mapped || m == guard)
      continue;
    if(fault_addr >= guard->addr && fault_addr < guard->addr + guard->length)
      return -1;
    if(fault_addr + PGSIZE >= guard->addr && fault_addr < guard->addr + guard->length)
      return -1;
  }
  return 0;
}

void*
pgfltpfhpgflthndlrintr() 
{
  struct proc *p = myproc();
  uint fault_addr = rcr2();
  
  cprintf("Entering for loop\n");
  for(int i = 0; i < 32; i++) {

    if(!p->map[i].mapped) {
      continue;
    }
    char *page = kalloc();
    // struct map_mem maps[32] = p->map;
    uint maxaddr = PGROUNDUP(((uint)p->map[i].addr) + p->map[i].length); 

    cprintf("fault_addr: %p, process mapp addr: %p, maxaddr: %p\n", fault_addr, p->map[i].addr, maxaddr);

    // Check whether the virtual address being accessed is within bounds
    if(fault_addr < p->map[i].addr || fault_addr >= maxaddr) {
      if(p->map[i].flags & MAP_GROWSUP) {
        if(check_guard_page(&p->map[i], fault_addr) < 0) {
          cprintf("Segmentation Fault\n");
          p->killed = 1;
          return MAP_FAIL;
        } 
      } else {
        cprintf("Virtual address out of bounds\n");
        cprintf("Segmentation Fault\n");
        p->killed = 1;
        return MAP_FAIL;
      }
    }

    pde_t *pte;

    // pte = walkpgdir(p->pgdir, fault_addr, maps[i]->length);

    // Check that the address of the pte associated with the virtual addresss is valid
    if((pte = walkpgdir(p->pgdir, (void*)fault_addr, p->map[i].length)) == 0) {
      cprintf("PTE not valid\n");
      cprintf("Segmentation Fault\n");
      p->killed = 1;
      return MAP_FAIL;
    }

    // Check physical address of the pte
    if(PTE_ADDR(&pte) == 0) {
      cprintf("Physical address of pte not valid\n");
      cprintf("Segmentation Fault\n");
      p->killed = 1;
      return MAP_FAIL;
    }

    cprintf("Checking flags...\n");

    // check for sharing 
    cprintf("Child shared flag: %x\n", p -> map[i].flags & MAP_SHARED);
    cprintf("Parent shared flag: %x\n", p -> parent -> map[i].flags & MAP_SHARED);
    if(p -> map[i].flags & MAP_SHARED && p -> parent->map[i].flags & MAP_SHARED){
      uint start = p -> map[i].addr; 
      uint stop = start + p -> map[i].length; 

      if(fault_addr >= start && fault_addr < stop){

        if(mappages(p->pgdir, (void *)fault_addr, PGSIZE, V2P(page), PTE_W | PTE_U) < 0){
          panic("mappages");
        }

      }else {
          cprintf("2\n");
          pte_t *pte = walkpgdir(p->parent->pgdir, (void *)fault_addr, 0);
          uint pa = PTE_ADDR(*pte);
          if(mappages(p->pgdir, (void*)fault_addr, PGSIZE, pa, PTE_W | PTE_U) < 0){
          panic("mappages");
        }
      }
    } else{
      cprintf("3\n");
      pte_t *pte = walkpgdir(p->parent->pgdir, (void *)fault_addr, 0);
      uint pa = PTE_ADDR(*pte);
      char *parent_pg = (char *)P2V(pa);
      memmove(page, parent_pg, PGSIZE);
      if(mappages(p->pgdir, (void *)fault_addr, PGSIZE, V2P(page), PTE_W | PTE_U) < 0){
          panic("mappages");
        }

    }

      // FILE-BACKED MAPPING
      if(!(p->map[i].flags & MAP_ANON)) { 
        cprintf("FILE BACKED MAPPING\n");
        fileread(p->map[i].f, (char*)(fault_addr), PGSIZE);
      }
           
    




    
    }

  return MAP_SUCCESS;
}
//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;
  case T_PGFLT:
    pgfltpfhpgflthndlrintr();
    break;


  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
