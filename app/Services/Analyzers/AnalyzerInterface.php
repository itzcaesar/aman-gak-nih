<?php

namespace App\Services\Analyzers;

use App\Models\Scan;

interface AnalyzerInterface
{
    /**
     * Analyze the given scan/URL and return a list of signals.
     *
     * @param Scan $scan
     * @return array Array of signal data [['type' => ..., 'weight' => ..., 'impact' => ..., 'description' => ...]]
     */
    public function analyze(Scan $scan, array $context = []): array;

    /**
     * Get the name/identifier of the analyzer.
     */
    public function name(): string;
}
