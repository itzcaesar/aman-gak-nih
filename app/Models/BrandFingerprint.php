<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BrandFingerprint extends Model
{
    protected $fillable = ['domain', 'brand_name', 'title_pattern', 'favicon_hash'];
}
