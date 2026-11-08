@echo off
rem 부스 실행 파일들이 함께 쓰는 파이썬 찾기(call 로 부른다, 저장소 맨 위에서). 결과: PYCMD
rem 1) var\booth\python.txt 에 적은 경로(git 밖, PC 마다 다름) 2) 저장소 .venv 3) py -3
rem 부스 스크립트는 서비스 모듈(safetrace.intake)을 쓰므로 백엔드 패키지가 깔린 파이썬이어야 한다
set "PYEXE="
set "PYCMD="
if exist "var\booth\python.txt" set /p PYEXE=<"var\booth\python.txt"
if not defined PYEXE if exist ".venv\Scripts\python.exe" set "PYEXE=%CD%\.venv\Scripts\python.exe"
if defined PYEXE (set PYCMD="%PYEXE%") else (set PYCMD=py -3)
%PYCMD% -c "import sqlalchemy, pydantic" >nul 2>nul && exit /b 0
echo.
echo [!] 백엔드 패키지가 깔린 파이썬을 찾지 못했습니다(찾은 것: %PYCMD%).
echo     저장소 맨 위에서:  py -3 -m venv .venv  그리고  .venv\Scripts\pip install -e backend
echo     또는 쓰려는 python.exe 경로 한 줄을 var\booth\python.txt 에 적으세요.
set "PYCMD="
exit /b 1
