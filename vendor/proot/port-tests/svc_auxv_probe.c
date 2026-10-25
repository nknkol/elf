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
void run(long *sp) {
 long argc=sp[0];char **av=(void*)(sp+1);char **env=av+argc+1;
 if(argc>1 && av[1][0]=='x') {
  char *args[]={"custom-zero","check",0};
  long r=sc(221,(long)"/probe",(long)args,(long)env,0,0,0);
  text("EXEC_ERROR=");num(r);goto fail;
 }
 while(*env)env++;
 unsigned long *aux=(void*)(env+1);long words=0;while(aux[words])words+=2;words+=2;
 unsigned long out[128];unsigned char shortbuf[2]={0,90};
 long bytes=words*8;
 if(sc(167,0x41555856,0,0,0,0,0)!=bytes)goto fail;
 if(sc(167,0x41555856,(long)out,sizeof(out),0,0,0)!=bytes)goto fail;
 for(long i=0;i<words;i++)if(aux[i]!=out[i])goto fail;
 if(sc(167,0x41555856,(long)shortbuf,1,0,0,0)!=bytes)goto fail;
 if(shortbuf[0]!=((unsigned char*)aux)[0]||shortbuf[1]!=90)goto fail;
 if(sc(167,0x41555856,1,16,0,0,0)!=-14)goto fail;
 if(sc(167,0x41555856,0,0,1,0,0)!=-22)goto fail;
 if(sc(167,0x41555856,0,0,0,1,0)!=-22)goto fail;
 for(long i=0;i<words;i+=2){
  if(aux[i]==31){text("EXECFN=");text((char*)aux[i+1]);text("\n");}
  if(aux[i]==7 && aux[i+1]!=0)goto fail; /* static executable */
 }
 text("AUXV_OK\n");sc(94,0,0,0,0,0,0);for(;;){}
 fail:text("AUXV_FAIL\n");sc(94,1,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
