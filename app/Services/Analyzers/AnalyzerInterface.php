<?php

namespace App\Services\Analyzers;

use App\Models\Scan;

interface AnalyzerInterface
{
    /**
     * Run the analyzer on the given scan.
     *
     * @param Scan $scan
     * @return array List of signals found (type, weight, impact, description)
     */
    public function analyze(Scan $scan): array;

    /**
     * Get the name of the analyzer.
     */
    public function name(): string;
}
