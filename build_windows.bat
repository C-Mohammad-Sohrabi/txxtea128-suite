@echo off
rem ============================================================
rem  xxtea-c — build every variant on Windows (cmd.exe)
rem
rem  Layout:
rem    .                     original XXTEA library (bench.c + xxtea.c)
rem    variants\variant_A..G experimental variants, each self-contained
rem
rem  Requirements:
rem    * MinGW-w64 gcc on PATH (e.g. WinLibs or MSYS2: pacman -S mingw-w64-x86_64-gcc)
rem    * For variants D/E/F: OpenSSL development files.
rem      If gcc cannot find openssl/hmac.h, point OPENSSL_CFLAGS /
rem      OPENSSL_LIBS below at your OpenSSL installation.
rem
rem  Run:  build_windows.bat
rem ============================================================
setlocal

set CFLAGS=-O2 -Wall -Wextra
set OPENSSL_CFLAGS=
set OPENSSL_LIBS=-lcrypto
rem Example for a local OpenSSL install:
rem set OPENSSL_CFLAGS=-IC:\OpenSSL-Win64\include
rem set OPENSSL_LIBS=-LC:\OpenSSL-Win64\lib\MinGW -lcrypto

echo == root bench (original xxtea library) ==
gcc %CFLAGS% -o bench.exe bench.c xxtea.c || goto :err

echo == variant_A ==
gcc %CFLAGS% -o variants\variant_A\bench_a.exe variants\variant_A\xxtea128.c variants\variant_A\bench_a.c || goto :err

echo == variant_B ==
gcc %CFLAGS% -o variants\variant_B\bench_b.exe variants\variant_B\txxtea128.c variants\variant_B\bench_b.c || goto :err

echo == variant_C ==
gcc %CFLAGS% -o variants\variant_C\bench_c.exe variants\variant_C\txxtea128_rs.c variants\variant_C\bench_c.c || goto :err

echo == variant_D (needs OpenSSL) ==
gcc %CFLAGS% %OPENSSL_CFLAGS% -o variants\variant_D\bench_etm.exe variants\variant_D\txxtea128.c variants\variant_D\txxtea_etm.c variants\variant_D\bench_etm.c %OPENSSL_LIBS% || goto :err
gcc %CFLAGS% %OPENSSL_CFLAGS% -o variants\variant_D\demo_etm.exe variants\variant_D\txxtea128.c variants\variant_D\txxtea_etm.c variants\variant_D\demo_etm.c %OPENSSL_LIBS% || goto :err

echo == variant_E (needs OpenSSL) ==
gcc %CFLAGS% %OPENSSL_CFLAGS% -o variants\variant_E\bench_etm_ctx.exe variants\variant_E\txxtea128.c variants\variant_E\txxtea_etm_ctx.c variants\variant_E\bench_etm_ctx.c %OPENSSL_LIBS% || goto :err

echo == variant_F (needs OpenSSL) ==
gcc %CFLAGS% %OPENSSL_CFLAGS% -o variants\variant_F\demo_aad.exe variants\variant_F\txxtea128.c variants\variant_F\txxtea_etm_aad.c variants\variant_F\demo_aad.c %OPENSSL_LIBS% || goto :err

echo == variant_G ==
gcc %CFLAGS% -o variants\variant_G\bench_g.exe variants\variant_G\txxtea128_h.c variants\variant_G\bench_g.c || goto :err

echo == test menu ==
gcc %CFLAGS% -o menu.exe menu.c || goto :err

echo.
echo All builds succeeded.
echo Run the test menu:  menu.exe
exit /b 0

:err
echo.
echo Build FAILED. See messages above.
exit /b 1