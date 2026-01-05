<?php
\App\Models\Scan::whereIn('status', ['pending', 'processing'])->update(['status' => 'failed']);
echo "Marked stuck scans (pending/processing) as failed.\n";
echo "Marked pending scans as failed.\n";
