@echo off
rem SafeTrace 부스 재생 멈춤(더블클릭): 멈춤 표시 파일을 만든다. 재생 창이 1초 안에 보고 요약을 남긴 뒤 끝난다
rem (조사 중인 사건은 그대로 끝까지 조사된다). 재생 중이 아니면 다음 시작 때 이 표시를 지운다.
chcp 65001 >nul
setlocal
cd /d "%~dp0.."
if not exist "var\booth" mkdir "var\booth"
type nul > "var\booth\STOP"
echo 멈춤 요청을 보냈습니다. 부스 재생 창에 요약이 나오고 끝납니다.
if not defined BOOTH_NOPAUSE timeout /t 5 >nul
endlocal
