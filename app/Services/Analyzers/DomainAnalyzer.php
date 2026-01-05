<?php

namespace App\Services\Analyzers;

use App\Models\Scan;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;


class DomainAnalyzer implements AnalyzerInterface
{
    public function name(): string
    {
        return 'Domain Identity & Age';
    }

    public function getAsyncRequests(Scan $scan): array
    {
        $apiNinjaKey = env('API_NINJA_KEY');
        if (!$apiNinjaKey) {
            return [];
        }

        $url = $scan->normalized_url;
        $host = parse_url($url, PHP_URL_HOST);
        $domain = preg_replace('/^www\./', '', $host);

        // Try to get root domain for subdomains (reusing logic from analyze - ideally refactor this out to private method but duplication is safer for now)
        $parts = explode('.', $domain);
        if (count($parts) > 2) {
            $multipartTlds = ['co.id', 'ac.id', 'go.id', 'sch.id', 'or.id', 'co.uk', 'com.sg', 'com.my', 'edu.my'];
            $tld2 = $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
            if (in_array($tld2, $multipartTlds)) {
                $domain = implode('.', array_slice($parts, -3));
            } else {
                $domain = implode('.', array_slice($parts, -2));
            }
        }

        return [
            'whois' => [
                'method' => 'GET',
                'url' => "https://api.api-ninjas.com/v1/whois?domain={$domain}",
                'headers' => ['X-Api-Key' => $apiNinjaKey],
                'options' => ['verify' => false, 'timeout' => 10]
            ]
        ];
    }

    public function analyze(Scan $scan, array $context = []): array
    {
        $signals = [];
        $url = $scan->normalized_url;
        $host = parse_url($url, PHP_URL_HOST);

        // Strip www. prefix
        $domain = preg_replace('/^www\./', '', $host);

        // Try to get root domain for subdomains
        $parts = explode('.', $domain);
        if (count($parts) > 2) {
            // Check for multipart TLDs
            $multipartTlds = ['co.id', 'ac.id', 'go.id', 'sch.id', 'or.id', 'co.uk', 'com.sg', 'com.my', 'edu.my'];
            $tld2 = $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];

            if (in_array($tld2, $multipartTlds)) {
                $domain = implode('.', array_slice($parts, -3));
            } else {
                $domain = implode('.', array_slice($parts, -2));
            }
        }

        $creationDate = null;
        $registrar = null;

        // API Ninja WHOIS (Exclusive Source)
        $apiNinjaKey = env('API_NINJA_KEY');

        if (!$apiNinjaKey) {
            Log::warning("API_NINJA_KEY is missing. Domain age check skipped.");
            $signals[] = [
                'type' => 'whois_unknown',
                'weight' => 0,
                'impact' => 'info',
                'description' => 'Konfigurasi server belum lengkap (API Key WHOIS hilang).'
            ];
            return $signals;
        }

        try {
            if (isset($context['whois'])) {
                $response = $context['whois'];
            } else {
                /** @var \Illuminate\Http\Client\Response $response */
                $response = Http::withoutVerifying()
                    ->withHeaders(['X-Api-Key' => $apiNinjaKey])
                    ->timeout(10)
                    ->get("https://api.api-ninjas.com/v1/whois?domain={$domain}");
            }

            if ($response->successful()) {
                $data = $response->json();

                // API Ninja returns creation_date as Unix timestamp or array
                if (isset($data['creation_date'])) {
                    $cd = $data['creation_date'];
                    $creationDate = is_array($cd) ? $cd[0] : $cd;
                }

                if (isset($data['registrar'])) {
                    $registrar = is_array($data['registrar']) ? $data['registrar'][0] : $data['registrar'];
                }
            } else {
                Log::warning("API Ninja WHOIS error for {$domain}: " . $response->body());
            }
        } catch (\Exception $e) {
            Log::warning("API Ninja WHOIS failed for {$domain}: " . $e->getMessage());
        }

        // Generate signals based on domain age
        if ($creationDate) {
            $age = time() - $creationDate;
            $ageDays = $age / 86400;
            $ageYears = round($ageDays / 365, 1);

            if ($ageDays < 30) {
                $signals[] = [
                    'type' => 'new_domain',
                    'weight' => -20, // Reduced from -40
                    'impact' => 'warning', // Reduced from critical
                    'description' => "Domain SANGAT BARU (berumur " . round($ageDays) . " hari). Waspada penipuan!",
                    'meta_data' => ['registrar' => $registrar, 'creation_date' => $creationDate]
                ];
            } elseif ($ageDays < 180) {
                $signals[] = [
                    'type' => 'young_domain',
                    'weight' => -5, // Reduced from -10 to minimize false positives
                    'impact' => 'warning',
                    'description' => "Domain relatif baru (berumur < 6 bulan). Gunakan dengan hati-hati.",
                    'meta_data' => ['registrar' => $registrar, 'creation_date' => $creationDate]
                ];
            } else {
                $signals[] = [
                    'type' => 'established_domain',
                    'weight' => 10,
                    'impact' => 'positive',
                    'description' => "Domain terpercaya (berumur {$ageYears} tahun).",
                    'meta_data' => ['registrar' => $registrar, 'creation_date' => $creationDate]
                ];
            }
        } else {
            $signals[] = [
                'type' => 'whois_unknown',
                'weight' => 0,
                'impact' => 'info',
                'description' => 'Data WHOIS tidak tersedia (Gagal menghubungi API atau Privacy Protected).'
            ];
        }

        return $signals;
    }
}
