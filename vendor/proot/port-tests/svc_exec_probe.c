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
void run(long *sp)
{
 long argc=sp[0]; char **av=(void*)(sp+1); char **env=av+argc+1;
 if(argc>2 && av[1][0]=='!') {
   char *args[]={"custom-zero","/mnt/file",0};
   char *vars[]={"PATH=/guest/bin","HOME=/guest",0};
   long ret;
   if(av[1][1]=='c')sc(49,(long)"/mnt",0,0,0,0,0);
   char m=av[1][1];
   if(m=='f'||m=='g'||m=='s'||m=='d'||m=='x'||m=='h') {
     /* s: O_PATH|O_NOFOLLOW symlink FD; x: O_CLOEXEC (script case). */
     long fd=sc(56,-100,(long)av[2],m=='s'?0x208000:m=='x'?0x80000:0,0,0,0);
     if(m=='g')sc(38,-100,(long)"/mnt/decoy",-100,(long)av[2],0,0); /* Swap the name. */
     if(m=='d')sc(35,-100,(long)av[2],0,0,0,0);                    /* Delete it. */
     /* h: AT_SYMLINK_NOFOLLOW on a regular file FD still executes it. */
     ret=sc(281,fd,(long)"",(long)args,(long)vars,m=='h'?4096|256:4096,0);
   } else if(av[1][1]=='a'||av[1][1]=='n'||av[1][1]=='e') {
     long fd=sc(56,-100,(long)"/mnt",0,0,0,0);
     ret=sc(281,fd,(long)av[2],(long)args,(long)vars,av[1][1]=='n'?256:av[1][1]=='e'?4096:0,0);
   } else ret=sc(221,(long)av[2],(long)args,av[1][1]=='z'?0:(long)vars,0,0,0);
   text("RET=");num(ret);
 } else {
   for(long i=0;i<argc;i++){text("ARG=");text(av[i]);text("\n");}
   for(;*env;env++){text("ENV=");text(*env);text("\n");}
   char cwd[256];long r=sc(17,(long)cwd,256,0,0,0,0);if(r>0){text("CWD=");text(cwd);text("\n");}
   const char *paths[]={"/real/file","/mnt/file"};
   for(int i=0;i<2;i++){long fd=sc(56,-100,(long)paths[i],0,0,0,0);text("OPEN=");num(fd<0?fd:0);if(fd>=0){char b[64];long n=sc(63,fd,(long)b,64,0,0,0);if(n>0)sc(64,1,(long)b,n,0,0,0);}}
 }
 sc(94,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
