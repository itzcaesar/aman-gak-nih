@echo off
echo Starting amangaknih.id Development Environment...
echo.

start "Laravel Server" php artisan serve
start "Queue Worker" cmd /k php artisan queue:work database --sleep=3 --tries=3 -v
start "Vite Dev" npm run dev

echo Services started!
echo Server: http://localhost:8000
echo.
pause
