@echo off
echo [RESET] Wiping Database and Cache...
php artisan migrate:fresh
php artisan cache:clear
echo [RESET] Cleanup Complete. Ready for fresh scans.
pause
