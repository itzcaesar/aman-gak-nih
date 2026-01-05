<?php

namespace App\Services;

use App\Models\Scan;

class RiskScoringService
{
    /**
     * Calculate final score and update scan.
     *
     * @param Scan $scan
     * @return void
     */
    public function calculate(Scan $scan): void
    {
        $signals = $scan->signals;
        $baseScore = 80; // Start with benefit of the doubt (Fairer for new sites)
        $totalWeight = 0;

        foreach ($signals as $signal) {
            $totalWeight += $signal->weight;
        }

        $finalScore = $baseScore + $totalWeight;

        // Clamp 0-100
        $finalScore = max(0, min(100, $finalScore));

        // Determine Level - adjusted thresholds for fairness
        if ($finalScore < 40) {
            $level = 'dangerous'; // Berbahaya - consistently bad signals
        } elseif ($finalScore < 75) {
            $level = 'suspicious'; // Mencurigakan - some flags or brand new
        } else {
            $level = 'safe'; // Relatif Aman - default for neutral/clean sites
        }

        $scan->update([
            'final_score' => $finalScore,
            'risk_level' => $level,
            'status' => 'completed'
        ]);
    }
}
