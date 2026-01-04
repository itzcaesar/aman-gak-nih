<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Signal extends Model
{
    protected $fillable = ['scan_id', 'type', 'weight', 'impact', 'description'];

    public function scan()
    {
        return $this->belongsTo(Scan::class);
    }
}
