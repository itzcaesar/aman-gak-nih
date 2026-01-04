<?php
$scan = \App\Models\Scan::find(1);
if ($scan) {
    echo "Scan ID: 1\n";
    echo "Status: " . $scan->status . "\n";
    echo "Score: " . $scan->final_score . "\n";
    echo "Signals: " . $scan->signals()->count() . "\n";
} else {
    echo "Scan 1 not found.\n";
}
