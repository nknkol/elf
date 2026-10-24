/* Freestanding AArch64: only reads our fixture. No libc or external files. */
#ifndef FIXTURE
#error FIXTURE must be an absolute path string
#endif
typedef unsigned int u32;
__attribute__((noinline)) static long sc(long n,long a,long b,long c,long d,long e,long f) {
 register long x8 __asm__("x8")=n;
 register long x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c;
 register long x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
 __asm__ volatile(".global probe_svc\nprobe_svc:\nsvc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5) : "memory","cc");
 return x0;
}
static void say(const char *s) { long n=0; while(s[n])n++; sc(64,1,(long)s,n,0,0,0); }
static void number(long x) {
 char b[32]; int p=31;b[p--]='\n'; unsigned long v=x<0?-x:x;
 do {b[p--]='0'+v%10;v/=10;}while(v);if(x<0)b[p--]='-';
 sc(64,1,(long)(b+p+1),31-p,0,0,0);
}
static void flush(void *p) {
 __asm__ volatile("dc cvau, %0\n dsb ish\n ic ivau, %0\n dsb ish\n isb"::"r"(p):"memory");
}
static void emit(volatile u32 *p) { p[0]=0xd2800708; p[1]=0xd4000001; p[2]=0xd65f03c0; flush((void*)p); }
void run(long *sp) {
 char mode=sp[0]>1?((char*)sp[2])[0]:'b';
 say("MODE=");sc(64,1,(long)&mode,1,0,0,0);say("\n");
 long fd;
 if(mode=='p') {
  extern u32 probe_svc[];
  u32 insn=*probe_svc;
  if((insn & 0xfc000000)!=0x14000000){say("NO_HOOK_STUB\n");goto done;}
  long off=((long)(int)(insn<<6))>>4;
  char *stub=(char*)probe_svc+off;
  unsigned long entry=*(unsigned long*)(stub+0xa0);
  long (*raw)(long,long,long,long,long,long,long)=(void*)(entry+RAW_DELTA);
  fd=raw(56,-100,(long)FIXTURE,0,0,0,0);
 } else if(mode=='b') fd=sc(56,-100,(long)FIXTURE,0,0,0,0);
 else {
  /* a: anonymous RWX then write; x: RW -> RWX then write; r: RW emit -> RX. */
  long page=sc(222,0,4096,mode=='a'?7:3,0x22,-1,0);
  if(page<0){say("MMAP_ERROR=");number(page);goto done;}
  if(mode=='r')emit((void*)page);
  if(mode!='a'){
   long rc=sc(226,page,4096,mode=='r'?5:7,0,0,0);
   if(rc<0){say("MPROTECT_ERROR=");number(rc);goto done;}
  }
  if(mode!='r')emit((void*)page);
  say("SVC_WORD=");number(((volatile u32*)page)[1]);
  fd=((long(*)(long,long,long,long,long,long))page)(-100,(long)FIXTURE,0,0,0,0);
 }
 if(fd<0){say("OPEN_ERROR=");number(fd);goto done;}
 char buf[64];long n=sc(63,fd,(long)buf,sizeof(buf),0,0,0);
 say("CONTENT=");if(n>0)sc(64,1,(long)buf,n,0,0,0);else number(n);
 sc(57,fd,0,0,0,0,0);
 done: sc(94,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
