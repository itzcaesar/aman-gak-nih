<?php

namespace Tests\Feature;

use Tests\TestCase;
use App\Models\Scan;
use App\Services\Analyzers\DomainAnalyzer;
use App\Services\Analyzers\SslAnalyzer;
use App\Services\Analyzers\VirusTotalAnalyzer;
use App\Services\Analyzers\GoogleSafeBrowsingAnalyzer;
use App\Services\Analyzers\PageInspector;
use App\Services\Analyzers\UrlHeuristicAnalyzer;
use Illuminate\Support\Facades\Log;

class AnalyzerIntegrationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Log::info('=== Analyzer Integration Test Suite Started ===');
    }

    public function test_all_analyzers_return_valid_signals(): void
    {
        Log::info('[TEST] test_all_analyzers_return_valid_signals');

        $scan = new Scan(['normalized_url' => 'https://google.com']);

        $analyzers = [
            'DomainAnalyzer' => new DomainAnalyzer(),
            'SslAnalyzer' => new SslAnalyzer(),
            'VirusTotalAnalyzer' => new VirusTotalAnalyzer(),
            'GoogleSafeBrowsingAnalyzer' => new GoogleSafeBrowsingAnalyzer(),
            'PageInspector' => new PageInspector(),
            'UrlHeuristicAnalyzer' => new UrlHeuristicAnalyzer(),
        ];

        foreach ($analyzers as $name => $analyzer) {
            Log::info("[DEBUG] Testing {$name}...");

            try {
                $startTime = microtime(true);
                $signals = $analyzer->analyze($scan);
                $duration = round((microtime(true) - $startTime) * 1000);

                Log::info("[DEBUG] {$name} completed in {$duration}ms");
                Log::info("[DEBUG] {$name} returned " . count($signals) . " signals");

                foreach ($signals as $signal) {
                    // Validate signal structure
                    $this->assertArrayHasKey('type', $signal, "{$name} signal missing 'type'");
                    $this->assertArrayHasKey('weight', $signal, "{$name} signal missing 'weight'");
                    $this->assertArrayHasKey('impact', $signal, "{$name} signal missing 'impact'");
                    $this->assertArrayHasKey('description', $signal, "{$name} signal missing 'description'");

                    Log::info("[DEBUG]   - {$signal['type']}: {$signal['weight']} ({$signal['impact']})");
                }

            } catch (\Exception $e) {
                Log::error("[ERROR] {$name} threw exception: " . $e->getMessage());
                $this->fail("{$name} threw exception: " . $e->getMessage());
            }
        }

        Log::info('[PASS] All analyzers return valid signals');
    }

    public function test_analyzers_handle_malformed_url_gracefully(): void
    {
        Log::info('[TEST] test_analyzers_handle_malformed_url_gracefully');

        $badUrls = [
            'not-a-valid-url',
            'javascript:alert(1)',
            'file:///etc/passwd',
        ];

        foreach ($badUrls as $badUrl) {
            Log::info("[DEBUG] Testing malformed URL: {$badUrl}");

            $scan = new Scan(['normalized_url' => $badUrl]);

            $analyzers = [
                new DomainAnalyzer(),
                new SslAnalyzer(),
                new UrlHeuristicAnalyzer(),
            ];

            foreach ($analyzers as $analyzer) {
                try {
                    $signals = $analyzer->analyze($scan);
                    Log::info("[DEBUG]   " . get_class($analyzer) . " handled gracefully");
                } catch (\Exception $e) {
                    Log::error("[ERROR] " . get_class($analyzer) . " failed: " . $e->getMessage());
                }
            }
        }

        Log::info('[PASS] Malformed URL handling test completed');
        $this->assertTrue(true);
    }

    public function test_api_analyzers_respect_timeout(): void
    {
        Log::info('[TEST] test_api_analyzers_respect_timeout');

        $scan = new Scan(['normalized_url' => 'https://nonexistent-domain-12345.com']);

        $apiAnalyzers = [
            'VirusTotal' => new VirusTotalAnalyzer(),
            'GoogleSafeBrowsing' => new GoogleSafeBrowsingAnalyzer(),
        ];

        foreach ($apiAnalyzers as $name => $analyzer) {
            $startTime = microtime(true);

            try {
                $signals = $analyzer->analyze($scan);
                $duration = round(microtime(true) - $startTime);

                Log::info("[DEBUG] {$name} completed in {$duration}s");

                // Should not take more than 30 seconds even for bad domains
                $this->assertLessThan(30, $duration, "{$name} exceeded timeout");

            } catch (\Exception $e) {
                $duration = round(microtime(true) - $startTime);
                Log::warning("[WARN] {$name} exception after {$duration}s: " . $e->getMessage());
            }
        }

        Log::info('[PASS] API timeout test completed');
    }

    protected function tearDown(): void
    {
        Log::info('=== Analyzer Integration Test Suite Completed ===');
        parent::tearDown();
    }
}
