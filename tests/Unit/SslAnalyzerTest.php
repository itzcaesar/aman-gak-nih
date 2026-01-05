<?php

namespace Tests\Unit;

use Tests\TestCase;
use App\Models\Scan;
use App\Services\Analyzers\SslAnalyzer;
use Illuminate\Support\Facades\Log;

class SslAnalyzerTest extends TestCase
{
    protected SslAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new SslAnalyzer();
        Log::info('=== SslAnalyzer Test Suite Started ===');
    }

    public function test_analyzer_has_correct_name(): void
    {
        Log::info('[TEST] test_analyzer_has_correct_name');
        $this->assertEquals('SSL/Transport Security', $this->analyzer->name());
        Log::info('[PASS] Analyzer name is correct');
    }

    public function test_https_site_returns_ssl_signal(): void
    {
        Log::info('[TEST] test_https_site_returns_ssl_signal');

        $scan = new Scan(['normalized_url' => 'https://google.com']);
        $signals = $this->analyzer->analyze($scan);

        Log::info('[DEBUG] SSL signals: ' . json_encode($signals, JSON_PRETTY_PRINT));

        $this->assertNotEmpty($signals);

        $types = array_column($signals, 'type');
        Log::info('[DEBUG] Signal types: ' . implode(', ', $types));

        $this->assertTrue(
            in_array('ssl_valid', $types) ||
            in_array('ssl_expired', $types) ||
            in_array('ssl_connection_failed', $types),
            'Should return an SSL-related signal'
        );

        Log::info('[PASS] HTTPS SSL test passed');
    }

    public function test_http_site_returns_no_https_signal(): void
    {
        Log::info('[TEST] test_http_site_returns_no_https_signal');

        $scan = new Scan(['normalized_url' => 'http://example.com']);
        $signals = $this->analyzer->analyze($scan);

        Log::info('[DEBUG] HTTP signals: ' . json_encode($signals, JSON_PRETTY_PRINT));

        $this->assertNotEmpty($signals);

        $types = array_column($signals, 'type');
        $this->assertContains('no_https', $types, 'Should flag no HTTPS');

        Log::info('[PASS] HTTP no-HTTPS test passed');
    }

    protected function tearDown(): void
    {
        Log::info('=== SslAnalyzer Test Suite Completed ===');
        parent::tearDown();
    }
}
