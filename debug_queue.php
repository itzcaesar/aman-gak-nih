<?php
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

echo "Queue Connection: " . Config::get('queue.default') . "\n";
echo "DB Driver: " . Config::get('database.default') . "\n";
echo "Jobs in DB: " . DB::table('jobs')->count() . "\n";
echo "Recent Scans: " . \App\Models\Scan::latest()->take(3)->get()->map(fn($s) => "ID: {$s->id} Status: {$s->status}")->implode(', ') . "\n";
