<?php

namespace App\Http\Controllers;

use App\Jobs\RunWebsiteScanJob;
use App\Models\Scan;
use App\Services\UrlNormalizer;
use Illuminate\Http\Request;
use Inertia\Inertia;

class ScanController extends Controller
{
    protected $normalizer;

    public function __construct(UrlNormalizer $normalizer)
    {
        $this->normalizer = $normalizer;
    }

    public function index()
    {
        return Inertia::render('Welcome');
    }

    public function store(Request $request)
    {
        $url = $request->input('url');
        // Prepend https:// if protocol is missing (for validation's sake)
        if ($url && !preg_match("~^(?:f|ht)tps?://~i", $url)) {
            $url = "https://" . $url;
            $request->merge(['url' => $url]);
        }

        $request->validate([
            'url' => 'required|url'
        ]);

        try {
            $normalizedUrl = $this->normalizer->normalize($request->input('url'));
        } catch (\InvalidArgumentException $e) {
            return back()->withErrors(['url' => $e->getMessage()]);
        }

        // Check for recent cached scan (within 1 hour)
        $existingScan = Scan::where('normalized_url', $normalizedUrl)
            ->where('status', 'completed')
            ->where('created_at', '>=', now()->subHour())
            ->latest()
            ->first();

        if ($existingScan) {
            return to_route('scan.show', $existingScan);
        }

        $scan = Scan::create([
            'normalized_url' => $normalizedUrl,
            'status' => 'pending'
        ]);

        \Illuminate\Support\Facades\Log::info("Dispatching scan ID: {$scan->id}");
        RunWebsiteScanJob::dispatch($scan->id);

        return to_route('scan.show', $scan);
    }

    public function show(Scan $scan)
    {
        // Ensure we have the freshest data from DB
        $scan->refresh();
        $scan->load('signals');

        \Illuminate\Support\Facades\Log::info("Returning Scan ID: {$scan->id} Status: {$scan->status}");

        return Inertia::render('Results', [
            'scan' => $scan // Inertia handles model serialization automatically
        ]);
    }
}
