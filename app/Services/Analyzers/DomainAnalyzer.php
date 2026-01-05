<?php

namespace App\Services\Analyzers;

use App\Models\Scan;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Iodev\Whois\Factory;

class DomainAnalyzer implements AnalyzerInterface
{
    public function name(): string
    {
        return 'Domain Identity & Age';
    }

    public function analyze(Scan $scan): array
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

        // Method 1: API Ninja WHOIS (Primary - more reliable)
        $apiNinjaKey = env('API_NINJA_KEY');
        if ($apiNinjaKey) {
            try {
                $response = Http::withoutVerifying()
                    ->withHeaders(['X-Api-Key' => $apiNinjaKey])
                    ->timeout(10)
                    ->get("https://api.api-ninjas.com/v1/whois?domain={$domain}");

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
                }
            } catch (\Exception $e) {
                Log::warning("API Ninja WHOIS failed for {$domain}: " . $e->getMessage());
            }
        }

        // Method 2: php-whois library (Fallback)
        if (!$creationDate) {
            try {
                $whois = Factory::get()->createWhois();
                $info = $whois->loadDomainInfo($domain);

                if ($info && $info->creationDate) {
                    $creationDate = $info->creationDate;
                }
            } catch (\Exception $e) {
                Log::warning("php-whois failed for {$domain}: " . $e->getMessage());
            }
        }

        // Generate signals based on domain age
        if ($creationDate) {
            $age = time() - $creationDate;
            $ageDays = $age / 86400;
            $ageYears = round($ageDays / 365, 1);

            if ($ageDays < 30) {
                $signals[] = [
                    'type' => 'new_domain',
                    'weight' => -40,
                    'impact' => 'critical',
                    'description' => "Domain SANGAT BARU (berumur " . round($ageDays) . " hari). Waspada penipuan!",
                    'meta_data' => ['registrar' => $registrar, 'creation_date' => $creationDate]
                ];
            } elseif ($ageDays < 180) {
                $signals[] = [
                    'type' => 'young_domain',
                    'weight' => -15,
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
                'description' => 'Data WHOIS tidak tersedia (Privacy Protected atau TLD tidak didukung).'
            ];
        }

        return $signals;
    }
}
