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

        // Common TLDs that have 2 parts
        $multipartTlds = ['co.id', 'ac.id', 'go.id', 'sch.id', 'or.id', 'co.uk', 'com.sg', 'com.my', 'edu.my'];

        try {
            $whois = Factory::get()->createWhois();
            $info = null;

            // 1. Try exact host first
            try {
                $info = $whois->loadDomainInfo($host);
            } catch (\Exception $e) {
                // Ignore, try fallback
            }

            // 2. If valid host but no info, try stripping subdomains
            if (!$info) {
                $parts = explode('.', $host);
                $count = count($parts);

                // If we have at least 3 parts (e.g. sub.domain.com or domain.co.id)
                if ($count >= 3) {
                    // Check if it ends in a known multipart TLD
                    $tld2 = $parts[$count - 2] . '.' . $parts[$count - 1];

                    if (in_array($tld2, $multipartTlds)) {
                        // It's like google.co.id, so simple stripping might break it if it was sub.google.co.id
                        // If it is sub.google.co.id (4 parts), we want google.co.id
                        if ($count > 3) {
                            $rootDomain = implode('.', array_slice($parts, -3));
                            try {
                                $info = $whois->loadDomainInfo($rootDomain);
                            } catch (\Exception $e) {
                            }
                        }
                    } else {
                        // Standard generic TLD (example.com)
                        // sub.example.com -> example.com
                        $rootDomain = implode('.', array_slice($parts, -2));
                        try {
                            $info = $whois->loadDomainInfo($rootDomain);
                        } catch (\Exception $e) {
                        }
                    }
                }
            }

            if (!$info) {
                $signals[] = [
                    'type' => 'whois_unknown',
                    'weight' => 0,
                    'impact' => 'info', // Changed to info so it doesn't scare users if just missing
                    'description' => 'Data WHOIS publik tidak ditemukan (Privacy Protected atau TLD tidak didukung).'
                ];
                return $signals;
            }

            $creationDate = $info->creationDate;

            if ($creationDate) {
                // In seconds
                $age = time() - $creationDate;
                $ageDays = $age / 86400;
                $ageYears = round($ageDays / 365, 1);

                if ($ageDays < 30) {
                    $signals[] = [
                        'type' => 'new_domain',
                        'weight' => -40, // Increased penalty
                        'impact' => 'critical',
                        'description' => "Domain SANGAT BARU (berumur {$ageDays} hari). Waspada penipuan!"
                    ];
                } elseif ($ageDays < 180) {
                    // < 6 Months
                    $signals[] = [
                        'type' => 'young_domain',
                        'weight' => -15,
                        'impact' => 'warning',
                        'description' => "Domain relatif baru (berumur < 6 bulan). Gunakan dengan hati-hati."
                    ];
                } else {
                    $signals[] = [
                        'type' => 'established_domain',
                        'weight' => 10,
                        'impact' => 'positive',
                        'description' => "Domain terpercaya (berumur {$ageYears} tahun)."
                    ];
                }
            } else {
                $signals[] = [
                    'type' => 'whois_hidden_date',
                    'weight' => -5,
                    'impact' => 'info',
                    'description' => 'Tanggal pembuatan domain disembunyikan oleh pemilik.'
                ];
            }

        } catch (\Exception $e) {
            // Keep silent or log
            // Log::error($e);
        }

        return $signals;
    }
}
