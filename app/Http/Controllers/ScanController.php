<?php

namespace App\Http\Controllers;

use App\Jobs\RunWebsiteScanJob;
use App\Models\Scan;
use App\Services\UrlNormalizer;
use Illuminate\Http\Request;
use Inertia\Inertia;

class ScanController extends Controller
{
    // normalizer removed


    public function index()
    {
        return Inertia::render('Welcome');
    }

    public function store(\App\Http\Requests\StoreScanRequest $request, \App\Services\ScanService $service)
    {
        try {
            $scan = $service->handle($request->input('url'));
            return to_route('scan.show', $scan);
        } catch (\InvalidArgumentException $e) {
            return back()->withErrors(['url' => $e->getMessage()]);
        }
    }

    public function show(Scan $scan)
    {
        $scan->refresh();
        $scan->load('signals');

        return Inertia::render('Results', [
            'scan' => $scan
        ]);
    }
}
