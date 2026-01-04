<?php

namespace App\Http\Controllers;

use App\Jobs\RunWebsiteScanJob;
use App\Models\Scan;
use App\Services\UrlNormalizer;
use Illuminate\Http\Request;

class ScanController extends Controller
{
    protected $normalizer;

    public function __construct(UrlNormalizer $normalizer)
    {
        $this->normalizer = $normalizer;
    }

    public function index()
    {
        $recentScans = Scan::where('status', 'completed')
            ->latest()
            ->take(5)
            ->get();

        return view('welcome', compact('recentScans'));
    }

    public function store(Request $request)
    {
        $request->validate([
            'url' => 'required|string',
        ]);

        try {
            $normalizedUrl = $this->normalizer->normalize($request->url);

            // Check if recent scan exists (last 24 hours)
            $existingScan = Scan::where('normalized_url', $normalizedUrl)
                ->where('created_at', '>=', now()->subHours(24))
                ->where('status', 'completed')
                ->latest()
                ->first();

            if ($existingScan) {
                return redirect()->route('scan.show', $existingScan->id);
            }

            // Create new scan
            $scan = Scan::create([
                'normalized_url' => $normalizedUrl,
                'status' => 'pending'
            ]);

            // Dispatch Job
            RunWebsiteScanJob::dispatch($scan->id);

            return redirect()->route('scan.show', $scan->id);

        } catch (\InvalidArgumentException $e) {
            return back()->withErrors(['url' => $e->getMessage()])->withInput();
        }
    }

    public function show($id)
    {
        $scan = Scan::with('signals')->findOrFail($id);

        // If simple AJAX polling is needed, we can return JSON if requested
        if (request()->wantsJson()) {
            return response()->json($scan);
        }

        return view('results', compact('scan'));
    }
}
