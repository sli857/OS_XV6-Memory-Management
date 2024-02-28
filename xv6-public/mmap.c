#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "mmap.h"
#include "proc.h"
#include "elf.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"

void *mmap(void *addr, int length, int prot, int flags, int fd, int offset) {
    struct proc *curproc = myproc();
    
    if (length <= 0 || length > KERNBASE - MMAPBASE) {
        cprintf("Invalid length\n");
        return MAP_FAIL;
    }

    if (flags & MAP_FIXED && ((uint)addr % PGSIZE != 0)) {
        cprintf("Address is not page-aligned\n");
        return MAP_FAIL;
    }

    if (flags & MAP_FIXED && ((uint)addr < MMAPBASE || (uint)addr >= KERNBASE)) {
        cprintf("Address is not within bounds\n");
        return MAP_FAIL;
    }

    uint start = (flags & MAP_FIXED) ? (uint)addr : PGROUNDUP(MMAPBASE);
    struct map_mem *currmap = 0;
    
    if (!(flags & MAP_FIXED)) {
        for (int i = 0; i < MAX_MAPS; i++) {
            currmap = &curproc->map[i];
            if (!currmap->mapped) {
                start = PGROUNDUP(start);
                if (start + length >= KERNBASE) {
                    cprintf("Out of memory\n");
                    return MAP_FAIL;
                }
                break;
            }
            start = currmap->addr + currmap->length;
        }
    }

    // Initialize the new mapping
    currmap = &curproc->map[curproc->num_mappings];
    currmap->addr = start;
    currmap->length = length;
    currmap->prot = prot;
    currmap->flags = flags;
    currmap->offset = offset;
    currmap->mapped = 1;

    // Adjust protection bits
    if (prot & PROT_READ) {
        currmap->prot = (currmap->prot | PTE_U);
    }
    if (prot & PROT_WRITE) {
        currmap->prot = (currmap->prot | PTE_W);
    }
    
    // Handle file-backed mapping
    if (!(flags & MAP_ANONYMOUS)) {
        if (fd < 0 || fd >= NOFILE || (currmap->f = curproc->ofile[fd]) == 0) {
            cprintf("Invalid file descriptor\n");
            return MAP_FAIL;
        }
        filedup(currmap->f); // Increment the reference count of the file
        currmap->fd = fd;
    }

    // Update the process's mapping count
    curproc->num_mappings++;

    cprintf("Mapped at address %x\n", start);
    return (void *)start;
}

int munmap(void* addr, int length) {
    struct proc *curproc = myproc();

    if(((uint)addr % PGSIZE)){
        cprintf("Address is not page-aligned\n");
        return -1;
    }

    for(int i = 0; i < MAX_MAPS; i++){
        if(curproc -> map[i].addr == (uint)addr){
            
            uint starting_addr = curproc -> map[i].addr;

            uint anon = curproc->map[i].flags & MAP_ANON;
            uint shared = curproc->map[i].flags & MAP_SHARED;
            // Check for file backing
            if(shared && !anon){
                curproc->map[i].f->off = 0;
                if(filewrite(curproc -> map[i].f, (char *) starting_addr, length) < 0){
                    cprintf("filewrite failed\n");
                    return -1; 
                }
            }



            for(uint j = starting_addr; j < starting_addr + length; j+=PGSIZE){
                // Get the pte
                pte_t *pte = walkpgdir(curproc ->pgdir, (char*)j, 1);
                char *v;
                
                // Check if the pte is present in the pgtable
                if(*pte & PTE_P){
                    
                    uint pa = PTE_ADDR(*pte);

                    v = P2V(pa);
                    
                    // Free memory
                    kfree(v);

                    // Indicate the page is not present
                    *pte = *pte & ~PTE_P;

                }
            }

            curproc -> map[i].addr += length;
            curproc -> map[i].length -= length; 
        }
    }


    return 0;
}

