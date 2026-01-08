<?php

namespace App\Services;

use App\Jobs\RunWebsiteScanJob;
use App\Models\Scan;

class ScanService
{
    protected UrlNormalizer $normalizer;

    public function __construct(UrlNormalizer $normalizer)
    {
        $this->normalizer = $normalizer;
    }

    /**
     * Handle the scan request: Check cache or start new scan.
     *
     * @param string $rawUrl
     * @return Scan
     * @throws \InvalidArgumentException
     */
    public function handle(string $rawUrl): Scan
    {
        // 1. Normalize
        $normalizedUrl = $this->normalizer->normalize($rawUrl);

        // 2. Check Cache (1 hour)
        $existingScan = Scan::where('normalized_url', $normalizedUrl)
            ->where('status', 'completed')
            ->where('created_at', '>=', now()->subHour())
            ->latest()
            ->first();

        if ($existingScan) {
            return $existingScan;
        }

        // 3. Create New Scan
        $scan = Scan::create([
            'normalized_url' => $normalizedUrl,
            'status' => 'pending'
        ]);

        // 4. Dispatch Job
        RunWebsiteScanJob::dispatch($scan->id);

        return $scan;
    }
}
