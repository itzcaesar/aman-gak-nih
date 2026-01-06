<?php

namespace Tests\Feature;

use Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;

class SecurityHardeningTest extends TestCase
{
    use RefreshDatabase;

    public function test_security_headers_are_present(): void
    {
        $response = $this->get('/');

        $response->assertStatus(200);

        $response->assertHeader('X-Frame-Options', 'DENY');
        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $response->assertHeader('Strict-Transport-Security');
        $response->assertHeader('Content-Security-Policy');

        // Assert X-Powered-By is removed (Laravel/PHP version hiding)
        $this->assertFalse($response->headers->has('X-Powered-By'), "X-Powered-By header should be removed.");
    }

    public function test_bad_bots_are_blocked(): void
    {
        $response = $this->withHeaders([
            'User-Agent' => 'mj12bot'
        ])->get('/');

        $response->assertStatus(403);
    }

    public function test_rate_limiter_blocks_excessive_scans(): void
    {
        // 5 requests should pass
        for ($i = 0; $i < 5; $i++) {
            $this->post('/scan', ['url' => 'https://example.com'])->assertStatus(302);
        }

        // 6th request should fail with 429 Too Many Requests
        $this->post('/scan', ['url' => 'https://example.com'])
            ->assertStatus(429);
    }
}
