@echo off
rem SafeTrace 부스 재생(더블클릭): 단계형 시험 페이지(자체 제작 모의 사이트)만 3시간 동안 콘솔에 넣는다(tools\booth_feed.py).
rem 실제 피싱 사이트는 열지 않는다(운영사무국 11/15 답변). 실제 피드를 섞는 리허설은 명령 창에서 booth_start.cmd --ratio 0.4
rem 시작 전: docker compose --profile demo up -d, 콘솔의 자동 수집은 끈다(켜져 있으면 시작하지 않는다). 멈춤: tools\booth_stop.cmd 또는 Ctrl+C.
chcp 65001 >nul
setlocal
cd /d "%~dp0.."
call tools\booth_py.cmd || goto :done
title SafeTrace 부스 재생
echo SafeTrace 부스 재생을 시작합니다(3시간, 시험 페이지만). 멈추려면 tools\booth_stop.cmd 를 더블클릭하세요.
echo 1분마다 진행 줄이 나오고, 기록은 var\booth\ 에 남습니다.
echo.
%PYCMD% tools\booth_feed.py run --hours 3 --stats %*
echo.
echo 부스 재생이 끝났습니다. 위 요약을 확인하세요.
:done
if not defined BOOTH_NOPAUSE pause
endlocal
