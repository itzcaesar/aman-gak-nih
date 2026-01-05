<?php

namespace App\Jobs;

use App\Models\Scan;
use App\Models\Signal;
use App\Services\Analyzers\BrandDetector;
use App\Services\Analyzers\DomainAnalyzer;
use App\Services\Analyzers\PageInspector;
use App\Services\Analyzers\SslAnalyzer;
use App\Services\Analyzers\UrlHeuristicAnalyzer;
use App\Services\RiskScoringService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class RunWebsiteScanJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public $scanId;

    /**
     * The number of seconds the job can run before timing out.
     *
     * @var int
     */
    public $timeout = 120;

    /**
     * The number of times the job may be attempted.
     *
     * @var int
     */
    public $tries = 1;

    /**
     * Create a new job instance.
     */
    public function __construct(int $scanId)
    {
        $this->scanId = $scanId;
    }

    /**
     * Execute the job.
     */
    public function handle(
        RiskScoringService $riskScoringService,
        DomainAnalyzer $domainAnalyzer,
        SslAnalyzer $sslAnalyzer,
        UrlHeuristicAnalyzer $heuristicAnalyzer,
        PageInspector $pageInspector,
        BrandDetector $brandDetector,
        \App\Services\Analyzers\GoogleSafeBrowsingAnalyzer $gsbAnalyzer,
        \App\Services\Analyzers\VirusTotalAnalyzer $vtAnalyzer
    ): void {
        $scan = Scan::find($this->scanId);

        if (!$scan) {
            Log::error("Scan ID {$this->scanId} not found.");
            return;
        }

        $scan->update(['status' => 'processing']);

        $analyzers = [
            $domainAnalyzer,
            $sslAnalyzer,
            $heuristicAnalyzer,
            $pageInspector,
            $brandDetector,
            $gsbAnalyzer,
            $vtAnalyzer
        ];

        try {
            // 1. Pre-fetch external data concurrently
            $asyncConfigs = [];
            foreach ($analyzers as $analyzer) {
                if (method_exists($analyzer, 'getAsyncRequests')) {
                    $asyncConfigs = array_merge($asyncConfigs, $analyzer->getAsyncRequests($scan));
                }
            }

            $context = [];
            if (!empty($asyncConfigs)) {
                $responses = \Illuminate\Support\Facades\Http::pool(function (\Illuminate\Http\Client\Pool $pool) use ($asyncConfigs) {
                    $poolRequests = [];
                    foreach ($asyncConfigs as $key => $config) {
                        $getRequest = $pool->as($key);

                        // Apply Headers
                        if (!empty($config['headers'])) {
                            $getRequest->withHeaders($config['headers']);
                        }

                        // Apply Options
                        $options = $config['options'] ?? [];
                        if (isset($options['verify']) && !$options['verify']) {
                            $getRequest->withoutVerifying();
                        }
                        if (isset($options['timeout'])) {
                            $getRequest->timeout($options['timeout']);
                        }
                        // Handle explicit User-Agent in nested headers or options
                        if (isset($options['headers']['User-Agent'])) {
                            $getRequest->withUserAgent($options['headers']['User-Agent']);
                        }

                        // Add to pool
                        $method = strtoupper($config['method']);
                        if ($method === 'GET') {
                            $poolRequests[] = $getRequest->get($config['url']);
                        } elseif ($method === 'POST') {
                            $poolRequests[] = $getRequest->post($config['url'], $config['data'] ?? []);
                        }
                    }
                    return $poolRequests;
                });

                // Collect results
                foreach ($responses as $key => $response) {
                    if ($response instanceof \Illuminate\Http\Client\Response || $response instanceof \Exception) {
                        $context[$key] = $response; // Handled by analyzer (it checks logic)
                    }
                }
            }

            // 2. Run Analyzers (using context if available)
            foreach ($analyzers as $analyzer) {
                try {
                    $results = $analyzer->analyze($scan, $context);

                    foreach ($results as $result) {
                        $scan->signals()->create([
                            'type' => $result['type'],
                            'weight' => $result['weight'],
                            'impact' => $result['impact'],
                            'description' => $result['description'],
                            'meta_data' => $result['meta_data'] ?? null
                        ]);
                    }

                } catch (\Exception $e) {
                    Log::error("Analyzer failed: " . get_class($analyzer) . " - " . $e->getMessage());
                    // Continue to next analyzer
                }
            }

            // Calculate Score
            $riskScoringService->calculate($scan);

        } catch (\Exception $e) {
            $scan->update(['status' => 'failed']);
            Log::error("Scan job failed: " . $e->getMessage());
        }
    }
}
