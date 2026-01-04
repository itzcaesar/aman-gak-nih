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
        \App\Services\Analyzers\GoogleSafeBrowsingAnalyzer $gsbAnalyzer
    ): void {
        echo " [x] Processing Scan ID: {$this->scanId} \n";
        Log::info("Job started for Scan ID: {$this->scanId}");
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
            $gsbAnalyzer
        ];

        try {
            foreach ($analyzers as $analyzer) {
                try {
                    $results = $analyzer->analyze($scan);

                    foreach ($results as $result) {
                        $scan->signals()->create([
                            'type' => $result['type'],
                            'weight' => $result['weight'],
                            'impact' => $result['impact'],
                            'description' => $result['description']
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
