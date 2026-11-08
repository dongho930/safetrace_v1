@echo off
rem SafeTrace 부스 재생(더블클릭): 살아 있는 피싱 주소 : 단계형 시험 페이지 = 6:4 를 3시간 동안 콘솔에 넣는다(tools\booth_feed.py).
rem 시작 전: docker compose --profile demo up -d, 콘솔의 자동 수집은 끈다. 멈춤: tools\booth_stop.cmd 또는 이 창에서 Ctrl+C.
chcp 65001 >nul
setlocal
cd /d "%~dp0.."
call tools\booth_py.cmd || goto :done
title SafeTrace 부스 재생
echo SafeTrace 부스 재생을 시작합니다(3시간). 멈추려면 tools\booth_stop.cmd 를 더블클릭하세요.
echo 1분마다 진행 줄이 나오고, 기록은 var\booth\ 에 남습니다.
echo.
%PYCMD% tools\booth_feed.py run --hours 3 --stats %*
echo.
echo 부스 재생이 끝났습니다. 위 요약을 확인하세요.
:done
if not defined BOOTH_NOPAUSE pause
endlocal
