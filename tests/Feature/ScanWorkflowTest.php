<?php

namespace Tests\Feature;

use Tests\TestCase;
use App\Models\Scan;
use App\Jobs\RunWebsiteScanJob;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Foundation\Testing\RefreshDatabase;

class ScanWorkflowTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Log::info('=== ScanWorkflow Feature Test Suite Started ===');
    }

    public function test_scan_creation_via_api(): void
    {
        Log::info('[TEST] test_scan_creation_via_api');

        $response = $this->post('/scan', [
            'url' => 'https://google.com'
        ]);

        Log::info("[DEBUG] Response status: {$response->getStatusCode()}");

        $response->assertRedirect();

        $scan = Scan::latest()->first();
        $this->assertNotNull($scan);

        Log::info("[DEBUG] Created Scan ID: {$scan->id} | URL: {$scan->normalized_url}");
        Log::info('[PASS] Scan creation test passed');
    }

    public function test_scan_job_processes_correctly(): void
    {
        Log::info('[TEST] test_scan_job_processes_correctly');

        $scan = Scan::create([
            'original_url' => 'https://example.com',
            'normalized_url' => 'https://example.com/',
            'status' => 'pending'
        ]);

        Log::info("[DEBUG] Created test scan: {$scan->id}");

        // Run job synchronously
        $job = new RunWebsiteScanJob($scan->id);
        $job->handle(
            app(\App\Services\RiskScoringService::class),
            app(\App\Services\Analyzers\DomainAnalyzer::class),
            app(\App\Services\Analyzers\SslAnalyzer::class),
            app(\App\Services\Analyzers\UrlHeuristicAnalyzer::class),
            app(\App\Services\Analyzers\PageInspector::class),
            app(\App\Services\Analyzers\BrandDetector::class),
            app(\App\Services\Analyzers\GoogleSafeBrowsingAnalyzer::class),
            app(\App\Services\Analyzers\VirusTotalAnalyzer::class)
        );

        $scan->refresh();

        Log::info("[DEBUG] Post-job status: {$scan->status}");
        Log::info("[DEBUG] Signals count: {$scan->signals->count()}");
        Log::info("[DEBUG] Final score: {$scan->final_score}");
        Log::info("[DEBUG] Risk level: {$scan->risk_level}");

        foreach ($scan->signals as $signal) {
            Log::info("[DEBUG] Signal: {$signal->type} | Weight: {$signal->weight} | Impact: {$signal->impact}");
        }

        $this->assertEquals('completed', $scan->status);
        $this->assertNotNull($scan->final_score);
        $this->assertNotEmpty($scan->signals);

        Log::info('[PASS] Scan job processing test passed');
    }

    public function test_results_page_loads(): void
    {
        Log::info('[TEST] test_results_page_loads');

        $scan = Scan::create([
            'original_url' => 'https://test.com',
            'normalized_url' => 'https://test.com/',
            'status' => 'completed',
            'final_score' => 75,
            'risk_level' => 'safe'
        ]);

        $response = $this->get("/scan/{$scan->id}");

        Log::info("[DEBUG] Results page status: {$response->getStatusCode()}");

        $response->assertStatus(200);

        Log::info('[PASS] Results page load test passed');
    }

    public function test_url_normalization(): void
    {
        Log::info('[TEST] test_url_normalization');

        $testCases = [
            'google.com' => 'https://google.com/',
            'http://example.com' => 'http://example.com/',
            'https://www.test.org/path' => 'https://www.test.org/path',
        ];

        foreach ($testCases as $input => $expectedPattern) {
            $response = $this->post('/scan', ['url' => $input]);
            $scan = Scan::latest()->first();

            Log::info("[DEBUG] Input: {$input} => Normalized: {$scan->normalized_url}");

            $this->assertStringContainsString(
                parse_url($expectedPattern, PHP_URL_HOST),
                $scan->normalized_url
            );
        }

        Log::info('[PASS] URL normalization test passed');
    }

    protected function tearDown(): void
    {
        Log::info('=== ScanWorkflow Feature Test Suite Completed ===');
        parent::tearDown();
    }
}
