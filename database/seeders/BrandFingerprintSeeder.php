<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class BrandFingerprintSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $brands = [
            [
                'domain' => 'google.com',
                'brand_name' => 'Google',
                'title_pattern' => 'Google',
                'favicon_hash' => null, // To be filled if we implement hash check
            ],
            [
                'domain' => 'facebook.com',
                'brand_name' => 'Facebook',
                'title_pattern' => 'Facebook',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'instagram.com',
                'brand_name' => 'Instagram',
                'title_pattern' => 'Instagram',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'tokopedia.com',
                'brand_name' => 'Tokopedia',
                'title_pattern' => 'Tokopedia',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'shopee.co.id',
                'brand_name' => 'Shopee',
                'title_pattern' => 'Shopee',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'klikbca.com',
                'brand_name' => 'BCA',
                'title_pattern' => 'BCA',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'bri.co.id',
                'brand_name' => 'BRI',
                'title_pattern' => 'BRI',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'bankmandiri.co.id',
                'brand_name' => 'Mandiri',
                'title_pattern' => 'Mandiri',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'dana.id',
                'brand_name' => 'DANA',
                'title_pattern' => 'DANA',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'paypal.com',
                'brand_name' => 'PayPal',
                'title_pattern' => 'PayPal',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'netflix.com',
                'brand_name' => 'Netflix',
                'title_pattern' => 'Netflix',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'microsoft.com',
                'brand_name' => 'Microsoft',
                'title_pattern' => 'Microsoft',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'apple.com',
                'brand_name' => 'Apple',
                'title_pattern' => 'Apple',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'gojek.com',
                'brand_name' => 'Gojek',
                'title_pattern' => 'Gojek',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'grab.com',
                'brand_name' => 'Grab',
                'title_pattern' => 'Grab',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'ovo.id',
                'brand_name' => 'OVO',
                'title_pattern' => 'OVO',
                'favicon_hash' => null,
            ],
            [
                'domain' => 'linkaja.id',
                'brand_name' => 'LinkAja',
                'title_pattern' => 'LinkAja',
                'favicon_hash' => null,
            ],
        ];

        DB::table('brand_fingerprints')->insertOrIgnore($brands);
    }
}
