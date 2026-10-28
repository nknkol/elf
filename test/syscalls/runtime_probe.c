/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Freestanding guest. All file operations use ordinary SVC instructions. */
__attribute__((noinline)) static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static void text(const char *s){long n=0;while(s[n])n++;sc(64,1,(long)s,n,0,0,0);}
static void num(long x){char b[32];int i=31;b[i--]='\n';unsigned long v=x<0?-x:x;do{b[i--]='0'+v%10;v/=10;}while(v);if(x<0)b[i--]='-';sc(64,1,(long)(b+i+1),31-i,0,0,0);}
static long parse(const char *s){long x=0;while(*s>='0'&&*s<='9')x=x*10+*s++-'0';return x;}
static volatile int delivered;
static void handler(int signum) { delivered = signum; }
extern void restorer(void);
extern long child_clone(void *stack);
__asm__(".global restorer\nrestorer:\nmov x8, #139\nsvc #0\n"
        ".global child_clone\nchild_clone:\nmov x1, x0\nmov x0, #17\nmov x2, #0\nmov x3, #0\nmov x4, #0\nmov x8, #220\nsvc #0\ncbz x0, 1f\nret\n1:\nmov x0, #42\nmov x8, #94\nsvc #0\n");
void run(long *sp) {
 char **av=(void*)(sp+1);char mode=sp[0]>1?av[1][0]:'b';
 if(mode=='c') {
  long mem=sc(222,0,65536,3,0x22,-1,0);
  if(mem<0){text("MMAP=");num(mem);goto done;}
  long pid=child_clone((void*)(mem+65536));
  text("CLONE=");num(pid<0?pid:0);
  if(pid>0){int status=0;long w=sc(260,pid,(long)&status,0,0,0,0);text("WAIT=");num(w<0?w:0);text("STATUS=");num(status);}
 } else if(mode=='s') {
  struct {void (*handler)(int);unsigned long flags;void(*restorer)(void);unsigned long mask;} act={handler,0x04000000,restorer,0};
  long r=sc(134,10,(long)&act,0,8,0,0);text("ACTION=");num(r);
  if(!r){long pid=sc(172,0,0,0,0,0,0);sc(129,pid,10,0,0,0,0);text("SIGNAL=");num(delivered);}
 } else {
  const long blocked[]={293,435,437,265,426,427,452,97,40,51,268,41,39,272};
  for(unsigned i=0;i<sizeof(blocked)/sizeof(blocked[0]);i++){text("NR=");num(blocked[i]);text("RET=");num(sc(blocked[i],0,0,0,0,0,0));}
 }
 done:sc(94,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
