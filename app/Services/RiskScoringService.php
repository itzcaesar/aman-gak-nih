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
        $baseScore = 60; // Start at neutral-ish
        $totalWeight = 0;

        foreach ($signals as $signal) {
            $totalWeight += $signal->weight;
        }

        $finalScore = $baseScore + $totalWeight;

        // Clamp 0-100
        $finalScore = max(0, min(100, $finalScore));

        // Determine Level
        if ($finalScore < 40) {
            $level = 'dangerous'; // Berbahaya
        } elseif ($finalScore < 70) {
            $level = 'suspicious'; // Mencurigakan
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
