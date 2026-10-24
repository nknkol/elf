#!/usr/bin/env python3
import pathlib, subprocess, json
here=pathlib.Path(__file__).resolve().parent
src=here.parent.parent/'src'
(here/'host.txt').write_text('HOST_ORIGINAL\n')
(here/'mapped.txt').write_text('GUEST_MAPPED\n')
symbols=subprocess.check_output(['llvm-nm','-n',str(src/'payload/payload.bin')],text=True)
values={parts[2]:int(parts[0],16) for line in symbols.splitlines() if len(parts:=line.split())==3 and parts[2] in ['_start','raw_syscall']}
subprocess.run(['clang',f'-DRAW_DELTA={values["raw_syscall"]-values["_start"]}','-nostdlib','-static','-ffreestanding','-fno-builtin','-fno-stack-protector','-O1','-Wl,-e,_start',f'-DFIXTURE="{here}/host.txt"',str(here/'probe.c'),'-o',str(here/'probe')],check=True)
results=[]
for backend in ['native','loader']:
 for mode in ['b','r','a','x','p']:
  cmd=[str(here/'probe'),mode]
  if backend=='loader': cmd=[str(src/'elfloader'),'--mode','compat','-v',f'{here}/mapped.txt:{here}/host.txt','--']+cmd
  try:
   p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
   output=p.stdout; rc=p.returncode
  except subprocess.TimeoutExpired as e: output=str(e.stdout);rc='timeout'
  (here/f'{backend}-{mode}.log').write_text(output)
  results.append(dict(backend=backend,mode=mode,returncode=rc,output=output))
  print(backend,mode,'exit=',rc, '\n'+output[-1700:],flush=True)
(here/'results.json').write_text(json.dumps(results,indent=2))
# These expectations describe the measured current implementation, including
# the reproduced bypass. They are not an assertion that isolation is secure.
by={(r['backend'],r['mode']):r for r in results}
for r in results:
 if r['returncode'] != 0:
  raise SystemExit(f"Failed/crashed: {r['backend']} {r['mode']}: {r['returncode']}")
for key,expected in [(('native','b'),'HOST_ORIGINAL'),(('native','r'),'HOST_ORIGINAL'),(('loader','b'),'GUEST_MAPPED'),(('loader','r'),'GUEST_MAPPED'),(('loader','p'),'HOST_ORIGINAL')]:
 if 'CONTENT='+expected not in by[key]['output']:
  raise SystemExit(f'Behavior changed: {key}; inspect results.json')
print('Reproduced: anonymous RW->RX is intercepted; direct payload raw_syscall bypasses the bind.')
