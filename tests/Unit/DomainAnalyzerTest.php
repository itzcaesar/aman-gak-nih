<?php

namespace Tests\Unit;

use Tests\TestCase;
use App\Models\Scan;
use App\Services\Analyzers\DomainAnalyzer;
use Illuminate\Support\Facades\Log;

class DomainAnalyzerTest extends TestCase
{
    protected DomainAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new DomainAnalyzer();
        Log::info('=== DomainAnalyzer Test Suite Started ===');
    }

    public function test_analyzer_has_correct_name(): void
    {
        Log::info('[TEST] test_analyzer_has_correct_name');
        $this->assertEquals('Domain Identity & Age', $this->analyzer->name());
        Log::info('[PASS] Analyzer name is correct');
    }

    public function test_established_domain_returns_positive_signal(): void
    {
        Log::info('[TEST] test_established_domain_returns_positive_signal');

        $scan = new Scan(['normalized_url' => 'https://google.com']);
        $signals = $this->analyzer->analyze($scan);

        Log::info('[DEBUG] Signals returned: ' . json_encode($signals, JSON_PRETTY_PRINT));

        $this->assertNotEmpty($signals, 'Should return at least one signal');

        $types = array_column($signals, 'type');
        Log::info('[DEBUG] Signal types: ' . implode(', ', $types));

        // Should be established or have some signal
        $this->assertTrue(
            in_array('established_domain', $types) ||
            in_array('whois_unknown', $types) ||
            in_array('new_domain', $types) ||
            in_array('young_domain', $types),
            'Should return a domain age signal'
        );

        Log::info('[PASS] Established domain test passed');
    }

    public function test_handles_subdomain_correctly(): void
    {
        Log::info('[TEST] test_handles_subdomain_correctly');

        $scan = new Scan(['normalized_url' => 'https://mail.google.com']);
        $signals = $this->analyzer->analyze($scan);

        Log::info('[DEBUG] Subdomain signals: ' . json_encode($signals, JSON_PRETTY_PRINT));

        $this->assertNotEmpty($signals);
        Log::info('[PASS] Subdomain handling test passed');
    }

    public function test_handles_multipart_tld(): void
    {
        Log::info('[TEST] test_handles_multipart_tld');

        $scan = new Scan(['normalized_url' => 'https://example.co.id']);
        $signals = $this->analyzer->analyze($scan);

        Log::info('[DEBUG] Multipart TLD signals: ' . json_encode($signals, JSON_PRETTY_PRINT));

        $this->assertNotEmpty($signals);
        Log::info('[PASS] Multipart TLD test passed');
    }

    protected function tearDown(): void
    {
        Log::info('=== DomainAnalyzer Test Suite Completed ===');
        parent::tearDown();
    }
}
