#!/bin/bash
cd /c/anyWorkspace/nx/Nxus/tests || exit 1
echo "== cwd: $(pwd) =="
echo "== which gcc =="
which gcc; ls -la /mingw64/bin/gcc.exe
echo "== trivial compile (mingw) =="
/mingw64/bin/gcc -std=c11 -O2 -o trivial.exe trivial.c > t1.log 2>&1
echo "mingw_exit=$?"
echo "--- t1.log ---"
cat t1.log
echo "--- files ---"
ls -la
echo "== msys gcc =="
/usr/bin/gcc -std=c11 -O2 -o trivial2.exe trivial.c > t2.log 2>&1
echo "msys_exit=$?"
echo "--- t2.log ---"
cat t2.log
ls -la trivial2.exe 2>&1
