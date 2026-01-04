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

    public function analyze(Scan $scan): array
    {
        $key = env('GOOGLE_SAFE_BROWSING_KEY');
        if (empty($key)) {
            return [];
        }

        $url = $scan->normalized_url;
        $signals = [];

        try {
            $endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={$key}";

            $payload = [
                'client' => [
                    'clientId' => 'amangaknih-scanner',
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

            $response = Http::timeout(5)->post($endpoint, $payload);

            if ($response->successful()) {
                $data = $response->json();

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
                        'description' => 'Tidak ditemukan di database Google Safe Browsing.'
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
