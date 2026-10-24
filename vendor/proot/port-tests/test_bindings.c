/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "path/binding_core.h"
static unsigned checks;
static void mapping(const BindingTable *t, Side side, const char *in, const char *expected)
{
    char out[PATH_MAX];
    assert(binding_table_map(t,side,in,out)==0);
    assert(!strcmp(out,expected));
    checks++;
}
int main(void)
{
    const PathBinding entries[]={
        {"/mnt","/outside"}, {"/mnt/sub","/nested"},
        {"/duplicate","/old"}, {"/duplicate","/new"},
        {"/same","/same"}, {"/ancestor","/host"}
    };
    const BindingTable t={"/host/root",entries,6};
    assert(binding_table_validate(&t)==0);
    mapping(&t,GUEST,"/","/host/root");
    mapping(&t,GUEST,"/file","/host/root/file");
    mapping(&t,GUEST,"/mnt","/outside");
    mapping(&t,GUEST,"/mnt/","/outside/");
    mapping(&t,GUEST,"/mnt/file","/outside/file");
    mapping(&t,GUEST,"/mnt/sub/file","/nested/file");
    mapping(&t,GUEST,"/mnt-other/file","/host/root/mnt-other/file");
    mapping(&t,GUEST,"/duplicate/file","/new/file");
    mapping(&t,GUEST,"/same/file","/same/file");
    mapping(&t,HOST,"/outside/file","/mnt/file");
    mapping(&t,HOST,"/nested/file","/mnt/sub/file");
    mapping(&t,HOST,"/new/file","/duplicate/file");
    mapping(&t,HOST,"/host/root/file","/file");
    mapping(&t,HOST,"/host/root","/");
    mapping(&t,HOST,"/host/other","/ancestor/other");
    char out[PATH_MAX];
    assert(binding_table_map(&t,HOST,"/old/file",out)==-EXDEV); checks++;
    assert(binding_table_map(&t,HOST,"/not-visible/file",out)==-EXDEV); checks++;
    strcpy(out,"/mnt/file");
    assert(binding_table_map(&t,GUEST,out,out)==0 && !strcmp(out,"/outside/file")); checks++;
    const BindingTable identity={"/",NULL,0};
    mapping(&identity,GUEST,"/file","/file");
    mapping(&identity,HOST,"/file","/file");
    strcpy(out,"/a/file");
    assert(binding_replace_core(out,"/a","/")==1 && !strcmp(out,"/file")); checks++;
    strcpy(out,"/a");
    assert(binding_replace_core(out,"/a","/")==1 && !strcmp(out,"/")); checks++;
    char huge[PATH_MAX], before[PATH_MAX];
    memset(huge,'x',sizeof(huge));huge[0]='/';huge[PATH_MAX-2]=0;
    strcpy(out,"/a/file");strcpy(before,out);
    assert(binding_replace_core(out,"/a",huge)==-ENAMETOOLONG);
    assert(!strcmp(out,before));checks++;
    const char *invalid[]={"relative","/trailing/","/dot/./x","/dot/../x","/double//x"};
    for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++){
        BindingTable bad={invalid[i],NULL,0};
        assert(binding_table_validate(&bad)==-EINVAL);checks++;
    }
    PathBinding badbind={"/","/anything"};
    BindingTable bad={"/root",&badbind,1};
    assert(binding_table_validate(&bad)==-EINVAL);checks++;
    printf("%u binding checks passed.\n",checks);
    return 0;
}
