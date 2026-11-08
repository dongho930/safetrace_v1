@echo off
rem SafeTrace 부스 재생 상태(더블클릭): 가장 최근 기록의 요약(피드 몫·화면 엶·시험 페이지·자원)과 조사 컨테이너 좀비 수.
rem 재생을 멈추지 않는다.
chcp 65001 >nul
setlocal
cd /d "%~dp0.."
call tools\booth_py.cmd || goto :done
set "LAST="
for /f "delims=" %%f in ('dir /b /o-d "var\booth\*.jsonl" 2^>nul') do if not defined LAST set "LAST=%%f"
if not defined LAST (
  echo 아직 부스 재생 기록이 없습니다.
  goto :done
)
echo 기록: var\booth\%LAST%
%PYCMD% tools\booth_feed.py summary "var\booth\%LAST%"
echo.
echo 조사 컨테이너 좀비 프로세스 수(0 이어야 함):
rem Docker 가 꺼져 있으면 find 가 빈 입력을 세어 0 을 보이므로, ps 가 성공했을 때만 센다
docker compose exec -T agent ps -eo stat > "%TEMP%\safetrace_booth_ps.txt" 2>nul || goto :nodocker
find /c "Z" < "%TEMP%\safetrace_booth_ps.txt"
goto :done
:nodocker
echo   조사 컨테이너에 접속하지 못했습니다 - Docker Desktop 과 스택(docker compose --profile demo up -d)을 확인하세요.
:done
if not defined BOOTH_NOPAUSE pause
endlocal
