set BUILD_PATH=out/build/x64-Debug
::call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

cmake.exe -B %BUILD_PATH% -G "Ninja"  ^
-DCMAKE_BUILD_TYPE:STRING="Debug" ^
-DCMAKE_INSTALL_PREFIX:PATH="C:\works\noise-c\out\install\x64-Debug" ^
-DCMAKE_C_COMPILER:FILEPATH="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.36.32532/bin/Hostx64/x64/cl.exe" ^
-DCMAKE_CXX_COMPILER:FILEPATH="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.36.32532/bin/Hostx64/x64/cl.exe" ^
-DCMAKE_MAKE_PROGRAM="C:\PROGRAM FILES\MICROSOFT VISUAL STUDIO\2022\COMMUNITY\COMMON7\IDE\COMMONEXTENSIONS\MICROSOFT\CMAKE\Ninja\ninja.exe" ^
. 2>&1

cmake --build %BUILD_PATH%