<?php

use Illuminate\Support\Facades\Http;

require __DIR__ . '/../vendor/autoload.php';
$app = require_once __DIR__ . '/../bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

echo "--- Environmental Checks ---\n";
$vtKey = env('VIRUSTOTAL_API_KEY');
$gsbKey = env('GOOGLE_SAFE_BROWSING_KEY');

echo "VT Key Present: " . ($vtKey ? "YES (" . substr($vtKey, 0, 4) . "...)" : "NO") . "\n";
echo "GSB Key Present: " . ($gsbKey ? "YES (" . substr($gsbKey, 0, 4) . "...)" : "NO") . "\n";

if (!$vtKey && !$gsbKey) {
    echo "ERROR: Keys missing. Please add them to .env\n";
    exit;
}

if ($vtKey) {
    echo "\n--- Testing VirusTotal API ---\n";
    try {
        $response = Http::withHeaders(['x-apikey' => $vtKey])
            ->withoutVerifying()
            ->get("https://www.virustotal.com/api/v3/domains/google.com");

        echo "Status: " . $response->status() . "\n";
        if ($response->successful()) {
            echo "Success! VT API is working.\n";
        } else {
            echo "Failed! Body: " . substr($response->body(), 0, 200) . "...\n";
        }
    } catch (\Exception $e) {
        echo "Exception: " . $e->getMessage() . "\n";
    }
}

if ($gsbKey) {
    echo "\n--- Testing Google Safe Browsing API ---\n";
    try {
        $endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={$gsbKey}";
        $payload = [
            'client' => ['clientId' => 'test-script', 'clientVersion' => '1.0.0'],
            'threatInfo' => [
                'threatTypes' => ['MALWARE'],
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => [['url' => 'http://google.com']]
            ]
        ];

        $response = Http::withoutVerifying()->post($endpoint, $payload);
        echo "Status: " . $response->status() . "\n";
        if ($response->successful()) {
            echo "Success! GSB API is working.\n";
            echo "Response: " . $response->body() . "\n";
        } else {
            echo "Failed! Body: " . $response->body() . "\n";
        }
    } catch (\Exception $e) {
        echo "Exception: " . $e->getMessage() . "\n";
    }
}
