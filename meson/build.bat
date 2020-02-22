setlocal
set VSINSTALLDIR="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community"
set CC=clang-cl
set CXX=clang-cl
call meson build --backend vs2019
cd build
call MSBuild wally.sln -t:Build -p:Configuration=Release
cd ..
