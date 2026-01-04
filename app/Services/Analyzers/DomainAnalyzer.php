<?php

namespace App\Services\Analyzers;

use App\Models\Scan;
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

        try {
            $whois = Factory::get()->createWhois();
            $info = $whois->loadDomainInfo($host);

            if (!$info) {
                // If direct domain fails, try registering domain (remove subdomains) - simplified for MVP
                // For now, if failed, just return neutral
                $signals[] = [
                    'type' => 'whois_params_missing',
                    'weight' => 0,
                    'impact' => 'info',
                    'description' => 'Data WHOIS tidak ditemukan atau disembunyikan.'
                ];
                return $signals;
            }

            $creationDate = $info->creationDate;
            $registrar = $info->registrar;

            if ($creationDate) {
                $ageDays = (time() - $creationDate) / 86400;

                if ($ageDays < 30) {
                    $signals[] = [
                        'type' => 'new_domain',
                        'weight' => -30,
                        'impact' => 'critical',
                        'description' => "Domain sangat baru (berumur " . round($ageDays) . " hari). Sering digunakan untuk serangan sementara."
                    ];
                } elseif ($ageDays < 180) {
                    $signals[] = [
                        'type' => 'young_domain',
                        'weight' => -10,
                        'impact' => 'warning',
                        'description' => "Domain relatif baru (berumur " . round($ageDays) . " hari)."
                    ];
                } else {
                    $signals[] = [
                        'type' => 'established_domain',
                        'weight' => 10,
                        'impact' => 'positive',
                        'description' => "Domain sudah lama terdaftar (" . round($ageDays / 365, 1) . " tahun)."
                    ];
                }
            }

            // Privacy check (heuristic on registrar or content)
            // Note: php-whois info structure varies, keeping it simple for MVP.

        } catch (\Exception $e) {
            $signals[] = [
                'type' => 'whois_error',
                'weight' => 0,
                'impact' => 'info',
                'description' => 'Gagal mengambil data WHOIS: ' . $e->getMessage()
            ];
        }

        return $signals;
    }
}
