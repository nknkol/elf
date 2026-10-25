import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from run import extract_root

class ExtractionTests(unittest.TestCase):
    def archive(self, root, entries):
        archive=root/'fixture.tar'
        with tarfile.open(archive,'w') as tar:
            for name,kind,target in entries:
                m=tarfile.TarInfo(name)
                if kind=='link':m.type=tarfile.SYMTYPE;m.linkname=target;tar.addfile(m)
                elif kind=='hard':m.type=tarfile.LNKTYPE;m.linkname=target;tar.addfile(m)
                else:
                    data=target.encode();m.size=len(data);tar.addfile(m,io.BytesIO(data))
        return archive
    def test_guest_absolute_link_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);dest=root/'root';dest.mkdir()
            archive=self.archive(root,[('bin/sh','link','/bin/busybox'),('bin/busybox','file','fixture')])
            extract_root(archive,dest)
            self.assertEqual((dest/'bin/sh').readlink(),Path('/bin/busybox'))
            self.assertEqual((dest/'bin/busybox').read_text(),'fixture')
    def test_reject_unsafe_archives_before_writing(self):
        cases=[ [('../escape','file','x')], [('/absolute','file','x')],
               [('dir','link','/tmp'),('dir/escape','file','x')],
               [('dup','file','x'),('dup','file','y')], [('hard','hard','/etc/passwd')] ]
        for entries in cases:
            with self.subTest(entries=entries),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);dest=root/'root';dest.mkdir()
                with self.assertRaises(ValueError):extract_root(self.archive(root,entries),dest)
                self.assertEqual(list(dest.iterdir()),[])

if __name__=='__main__':unittest.main()
