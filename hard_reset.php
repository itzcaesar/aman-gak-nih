<?php
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

Schema::disableForeignKeyConstraints();
\App\Models\Signal::truncate();
\App\Models\Scan::truncate();
DB::table('jobs')->truncate();
DB::table('failed_jobs')->truncate();
Schema::enableForeignKeyConstraints();

echo "ALL DATA WIPED. READY FOR FRESH START.\n";
