/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "vm_write_guard.h"
int main(void)
{
    struct vm_write_guard g={0},before;
    assert(vm_write_add(&g,10,20)==0);
    assert(vm_write_add(&g,20,30)==0 && g.count==1);
    assert(vm_write_remove(&g,15,25)==0 && g.count==2);
    assert(vm_write_covers(&g,10,15) && !vm_write_covers(&g,10,26));
    assert(vm_write_add(&g,15,25)==0 && g.count==1);
    g.count=0;
    for(unsigned i=0;i<VM_WRITE_REGIONS;i++)assert(vm_write_add(&g,4*i,4*i+3)==0);
    before=g;
    assert(vm_write_add(&g,1000,1001)==-ENOSPC);
    assert(!memcmp(&g,&before,sizeof(g)));
    assert(vm_write_remove(&g,1,2)==-ENOSPC);
    assert(!memcmp(&g,&before,sizeof(g)));
    assert(vm_write_remove(&g,0,3)==0);
    assert(vm_write_add(&g,1000,1001)==0);
    /* Deterministic reference bitmap checks merging, splitting and holes. */
    g.count=0;unsigned char model[256]={0};unsigned seed=123;
    for(int step=0;step<3000;step++) {
        seed=seed*1664525u+1013904223u;unsigned begin=seed%255;
        seed=seed*1664525u+1013904223u;unsigned end=begin+1+seed%(256-begin);
        seed=seed*1664525u+1013904223u;int add=(seed>>16)&1;
        assert((add?vm_write_add(&g,begin,end):vm_write_remove(&g,begin,end))==0);
        for(unsigned i=begin;i<end;i++)model[i]=add;
        for(unsigned i=0;i<256;i++)assert(vm_write_covers(&g,i,i+1)==!!model[i]);
        for(size_t i=1;i<g.count;i++)assert(g.regions[i-1].end<g.regions[i].begin);
    }
    puts("PASS: VM interval model, capacity atomicity and reference bitmap");
    return 0;
}
