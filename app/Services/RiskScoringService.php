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
        $baseScore = 70; // Start with benefit of the doubt
        $totalWeight = 0;

        foreach ($signals as $signal) {
            $totalWeight += $signal->weight;
        }

        $finalScore = $baseScore + $totalWeight;

        // Clamp 0-100
        $finalScore = max(0, min(100, $finalScore));

        // Determine Level - adjusted thresholds
        if ($finalScore < 30) {
            $level = 'dangerous'; // Berbahaya - only truly bad sites
        } elseif ($finalScore < 60) {
            $level = 'suspicious'; // Mencurigakan - proceed with caution
        } else {
            $level = 'safe'; // Relatif Aman
        }

        $scan->update([
            'final_score' => $finalScore,
            'risk_level' => $level,
            'status' => 'completed'
        ]);
    }
}
