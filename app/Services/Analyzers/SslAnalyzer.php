<?php

namespace App\Services\Analyzers;

use App\Models\Scan;

class SslAnalyzer implements AnalyzerInterface
{
    public function name(): string
    {
        return 'SSL/Transport Security';
    }

    public function analyze(Scan $scan): array
    {
        $signals = [];
        $url = $scan->normalized_url;
        $parsed = parse_url($url);
        $scheme = $parsed['scheme'] ?? 'http';
        $host = $parsed['host'] ?? '';

        if ($scheme !== 'https') {
            $signals[] = [
                'type' => 'no_https',
                'weight' => -25,
                'impact' => 'critical',
                'description' => 'Website tidak menggunakan HTTPS. Komunikasi data tidak terenkripsi.'
            ];
            // Cannot check SSL certificate if not HTTPS
            return $signals;
        }

        // Check SSL Certificate
        $streamContext = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => true, // We want to know if it verify fails
                'verify_peer_name' => true,
                'timeout' => 5
            ]
        ]);

        $read = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $streamContext);

        if (!$read) {
            $signals[] = [
                'type' => 'ssl_connection_failed',
                'weight' => -20,
                'impact' => 'critical',
                'description' => "Gagal melakukan koneksi SSL ke hostname: $errstr"
            ];
            return $signals;
        }

        $params = stream_context_get_params($read);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;

        if ($cert) {
            $certInfo = openssl_x509_parse($cert);

            // Check Expiration
            $validTo = $certInfo['validTo_time_t'] ?? 0;
            $daysUntilExpr = ($validTo - time()) / 86400;

            if ($daysUntilExpr < 0) {
                $signals[] = [
                    'type' => 'ssl_expired',
                    'weight' => -30,
                    'impact' => 'critical',
                    'description' => 'Sertifikat SSL sudah kadaluwarsa.'
                ];
            } elseif ($daysUntilExpr < 7) {
                $signals[] = [
                    'type' => 'ssl_expiring_soon',
                    'weight' => -5,
                    'impact' => 'warning',
                    'description' => "Sertifikat SSL akan kadaluwarsa dalam " . round($daysUntilExpr) . " hari."
                ];
            } else {
                $signals[] = [
                    'type' => 'ssl_valid',
                    'weight' => 10,
                    'impact' => 'positive',
                    'description' => 'Sertifikat SSL valid dan aktif.'
                ];
            }

            // Check Issuer (Example: Let's Encrypt is okay, but maybe flag unverified ones? For MVP assume standard issuers ok)
            // Just recording valid SSL is enough positive signal for now.
        } else {
            $signals[] = [
                'type' => 'ssl_no_cert',
                'weight' => -20,
                'impact' => 'critical',
                'description' => 'Tidak dapat mengambil sertifikat SSL.'
            ];
        }

        return $signals;
    }
}
