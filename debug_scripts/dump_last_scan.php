<?php

require __DIR__ . '/../vendor/autoload.php';
$app = require_once __DIR__ . '/../bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

$scan = \App\Models\Scan::with('signals')->latest()->first();
if (!$scan) {
    echo "No scans found.\n";
    exit;
}
echo "Scan ID: " . $scan->id . "\n";
echo "Status: " . $scan->status . "\n";
echo "Signals Count: " . $scan->signals->count() . "\n";
echo json_encode($scan->signals->toArray(), JSON_PRETTY_PRINT);
