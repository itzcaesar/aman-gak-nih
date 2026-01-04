<?php
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Config;

echo "--- DEBUG INFO ---\n";
echo "Failed Jobs: " . DB::table('failed_jobs')->count() . "\n";
if (DB::table('failed_jobs')->count() > 0) {
    $fail = DB::table('failed_jobs')->latest()->first();
    echo "Last Failure: " . substr($fail->exception, 0, 200) . "...\n";
}
echo "Pending Scans: " . \App\Models\Scan::where('status', 'pending')->count() . "\n";
echo "Stuck Scan IDs: " . \App\Models\Scan::where('status', 'pending')->pluck('id')->implode(', ') . "\n";
