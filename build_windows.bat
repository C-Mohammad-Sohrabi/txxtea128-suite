@echo off
setlocal
gcc -O2 -Wall -Wextra -o bench.exe bench.c xxtea.c
if errorlevel 1 exit /b 1
gcc -O2 -Wall -Wextra -I. -o example\xxtea_example.exe example\test.c example\base64.c xxtea.c
if errorlevel 1 exit /b 1
exit /b 0
