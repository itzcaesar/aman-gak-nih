<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Signal extends Model
{
    protected $fillable = ['scan_id', 'type', 'weight', 'impact', 'description', 'meta_data'];

    protected $casts = [
        'meta_data' => 'array',
    ];

    public function scan()
    {
        return $this->belongsTo(Scan::class);
    }
}
