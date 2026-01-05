<?php

namespace Tests\Unit;

use Tests\TestCase;
use App\Models\Scan;
use App\Services\RiskScoringService;
use Illuminate\Support\Facades\Log;
use Illuminate\Foundation\Testing\RefreshDatabase;

class RiskScoringServiceTest extends TestCase
{
    use RefreshDatabase;

    protected RiskScoringService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new RiskScoringService();
        Log::info('=== RiskScoringService Test Suite Started ===');
    }

    public function test_positive_signals_result_in_safe_score(): void
    {
        Log::info('[TEST] test_positive_signals_result_in_safe_score');

        $scan = Scan::create([
            'original_url' => 'https://google.com',
            'normalized_url' => 'https://google.com',
            'status' => 'processing'
        ]);

        // Add positive signals
        $scan->signals()->create(['type' => 'ssl_valid', 'weight' => 10, 'impact' => 'positive', 'description' => 'SSL OK']);
        $scan->signals()->create(['type' => 'established_domain', 'weight' => 10, 'impact' => 'positive', 'description' => 'Old domain']);
        $scan->signals()->create(['type' => 'gsb_clean', 'weight' => 10, 'impact' => 'positive', 'description' => 'GSB OK']);

        $this->service->calculate($scan);
        $scan->refresh();

        Log::info("[DEBUG] Final Score: {$scan->final_score} | Level: {$scan->risk_level}");

        $this->assertGreaterThanOrEqual(60, $scan->final_score, 'Positive signals should result in score >= 60');
        $this->assertEquals('safe', $scan->risk_level);

        Log::info('[PASS] Positive signals scoring test passed');
    }

    public function test_negative_signals_result_in_lower_score(): void
    {
        Log::info('[TEST] test_negative_signals_result_in_lower_score');

        $scan = Scan::create([
            'original_url' => 'https://suspicious-site.xyz',
            'normalized_url' => 'https://suspicious-site.xyz',
            'status' => 'processing'
        ]);

        // Add negative signals
        $scan->signals()->create(['type' => 'new_domain', 'weight' => -40, 'impact' => 'critical', 'description' => 'New domain']);
        $scan->signals()->create(['type' => 'no_https', 'weight' => -25, 'impact' => 'critical', 'description' => 'No HTTPS']);

        $this->service->calculate($scan);
        $scan->refresh();

        Log::info("[DEBUG] Final Score: {$scan->final_score} | Level: {$scan->risk_level}");

        $this->assertLessThan(60, $scan->final_score, 'Negative signals should lower score');
        $this->assertNotEquals('safe', $scan->risk_level);

        Log::info('[PASS] Negative signals scoring test passed');
    }

    public function test_score_is_clamped_between_0_and_100(): void
    {
        Log::info('[TEST] test_score_is_clamped_between_0_and_100');

        $scan = Scan::create([
            'original_url' => 'https://test.com',
            'normalized_url' => 'https://test.com',
            'status' => 'processing'
        ]);

        // Add extreme negative signals
        $scan->signals()->create(['type' => 'malware', 'weight' => -100, 'impact' => 'critical', 'description' => 'Malware']);
        $scan->signals()->create(['type' => 'phishing', 'weight' => -100, 'impact' => 'critical', 'description' => 'Phishing']);

        $this->service->calculate($scan);
        $scan->refresh();

        Log::info("[DEBUG] Final Score: {$scan->final_score}");

        $this->assertGreaterThanOrEqual(0, $scan->final_score);
        $this->assertLessThanOrEqual(100, $scan->final_score);

        Log::info('[PASS] Score clamping test passed');
    }

    protected function tearDown(): void
    {
        Log::info('=== RiskScoringService Test Suite Completed ===');
        parent::tearDown();
    }
}
