setlocal
set VSINSTALLDIR="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community"
set CC=clang-cl.exe
set CXX=clang-cl.exe
call meson setup build --backend=ninja
call ninja -C build
