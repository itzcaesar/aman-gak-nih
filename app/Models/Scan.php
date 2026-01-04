<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Scan extends Model
{
    protected $fillable = ['normalized_url', 'final_score', 'risk_level', 'status'];

    public function signals()
    {
        return $this->hasMany(Signal::class);
    }
}
