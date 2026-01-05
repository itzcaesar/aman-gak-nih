@echo off
echo [RESET] Wiping Database and Cache...
php artisan migrate:fresh
php artisan optimize:clear
echo [RESET] Cleanup Complete. Ready for fresh scans.
pause
