<?php
\App\Models\Scan::where('status', 'pending')->update(['status' => 'failed']);
echo "Marked pending scans as failed.\n";
