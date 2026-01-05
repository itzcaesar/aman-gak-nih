<?php

namespace App\Services\Analyzers;

use App\Models\Scan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class GoogleSafeBrowsingAnalyzer implements AnalyzerInterface
{
    public function name(): string
    {
        return 'Google Safe Browsing';
    }

    public function getAsyncRequests(Scan $scan): array
    {
        $key = env('GOOGLE_SAFE_BROWSING_KEY');
        if (empty($key)) {
            return [];
        }

        $url = $scan->normalized_url;
        $endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={$key}";

        $payload = [
            'client' => [
                'clientId' => 'aman-gak-nih',
                'clientVersion' => '1.0.0'
            ],
            'threatInfo' => [
                'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => [
                    ['url' => $url]
                ]
            ]
        ];

        return [
            'gsb' => [
                'method' => 'POST',
                'url' => $endpoint,
                'data' => $payload,
                'options' => ['verify' => false, 'timeout' => 5]
            ]
        ];
    }

    public function analyze(Scan $scan, array $context = []): array
    {
        $signals = [];

        // Use pre-fetched response if available
        if (isset($context['gsb'])) {
            $response = $context['gsb'];
        } else {
            // Fallback to synchronous execution
            $requests = $this->getAsyncRequests($scan);
            if (empty($requests))
                return [];

            $req = $requests['gsb'];
            $response = Http::withoutVerifying()->timeout(5)->post($req['url'], $req['data']);
        }

        try {
            if ($response->successful()) {
                $data = $response->json();
                // Reconstruct payload for metadata (since we need it for the 'clean' signal)
                // We can either pass it in context or just re-generate it. Re-generating is cheap.
                $key = env('GOOGLE_SAFE_BROWSING_KEY'); // Env might be needed if we were generating requests strictly, but here we just need payload structure

                // Quick payload reconstruction for metadata
                $payload = $this->getAsyncRequests($scan)['gsb']['data'];

                if (!empty($data['matches'])) {
                    $signals[] = [
                        'type' => 'google_safe_browsing_match',
                        'weight' => -50, // Instant danger
                        'impact' => 'critical',
                        'description' => 'Terdeteksi berbahaya oleh Google Safe Browsing (Malware/Phishing).'
                    ];
                } else {
                    $signals[] = [
                        'type' => 'google_safe_browsing_clean',
                        'weight' => 10,
                        'impact' => 'positive',
                        'description' => 'Tidak ditemukan di database Google Safe Browsing.',
                        'meta_data' => [
                            'checked_threat_types' => $payload['threatInfo']['threatTypes'],
                            'platform_type' => 'ANY_PLATFORM'
                        ]
                    ];
                }
            } else {
                Log::warning('Google Safe Browsing API Error: ' . $response->status());
            }

        } catch (\Exception $e) {
            Log::error('Google Safe Browsing Scan Failed: ' . $e->getMessage());
        }

        return $signals;
    }
}
