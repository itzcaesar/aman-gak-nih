@extends('layout')

@section('title', 'Hasil Analisis - amangaknih.id')

@section('content')

@if($scan->status !== 'completed' && $scan->status !== 'failed')
    <!-- Loading State -->
    <div class="flex flex-col items-center justify-center min-h-[60vh] text-center animate-fade-in">
        <div class="relative w-24 h-24 mb-8">
            <div class="absolute inset-0 border-4 border-blue-500/30 rounded-full animate-ping"></div>
            <div class="absolute inset-0 border-4 border-t-blue-500 border-r-transparent border-b-transparent border-l-transparent rounded-full animate-spin"></div>
            <div class="absolute inset-2 bg-gray-800 rounded-full flex items-center justify-center">
                <span class="text-3xl">🔍</span>
            </div>
        </div>
        <h2 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-green-400 mb-4">
            Sedang Menganalisis...
        </h2>
        <p class="text-gray-400 max-w-md mx-auto">
            Kami sedang memindai domain, sertifikat SSL, dan pola keamanan lainnya. Mohon tunggu sebentar.
        </p>
        
        <script>
            setTimeout(function() {
                window.location.reload();
            }, 3000);
        </script>
    </div>
@else
    <!-- Dashboard Layout -->
    <div class="animate-fade-in space-y-6">
        
        <!-- Header -->
        <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-gray-800/50 p-6 rounded-2xl border border-gray-700 backdrop-blur-sm">
            <div>
                <h1 class="text-2xl md:text-3xl font-bold text-white break-all">
                    {{ parse_url($scan->normalized_url, PHP_URL_HOST) }}
                </h1>
                <p class="text-gray-400 text-sm mt-1">{{ $scan->normalized_url }}</p>
                <p class="text-gray-500 text-xs mt-2">ID Scan: #{{ $scan->id }} • {{ $scan->created_at->format('d M Y, H:i') }}</p>
            </div>
            <div class="flex gap-3">
                <a href="{{ route('home') }}" class="px-5 py-2.5 text-sm font-medium text-white bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                    Scan Baru
                </a>
                <button onclick="window.print()" class="px-5 py-2.5 text-sm font-medium text-gray-900 bg-white hover:bg-gray-100 rounded-lg transition-colors">
                    Cetak Laporan
                </button>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            <!-- Left Column: Score & Summary -->
            <div class="lg:col-span-1 space-y-6">
                <!-- Score Card -->
                <div class="bg-gray-800/80 p-8 rounded-2xl border border-gray-700 text-center relative overflow-hidden">
                    <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-green-500"></div>
                    
                    <h3 class="text-gray-400 font-medium uppercase tracking-wider text-sm mb-6">Trust Score</h3>
                    
                    <div class="relative w-48 h-48 mx-auto mb-6 flex items-center justify-center">
                        <!-- Simple CSS Gauge Background -->
                        <div class="w-full h-full rounded-full border-[12px] border-gray-700"></div>
                        <!-- Score Text -->
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-6xl font-extrabold text-white">{{ $scan->final_score }}</span>
                            <span class="text-sm text-gray-500">/ 100</span>
                        </div>
                    </div>

                    <div class="inline-block px-6 py-2 rounded-full font-bold text-lg uppercase tracking-wide border
                        @if($scan->risk_level == 'safe') bg-green-500/10 text-green-400 border-green-500/20
                        @elseif($scan->risk_level == 'suspicious') bg-yellow-500/10 text-yellow-400 border-yellow-500/20
                        @else bg-red-500/10 text-red-500 border-red-500/20
                        @endif">
                        @if($scan->risk_level == 'safe') ✅ Relatif Aman
                        @elseif($scan->risk_level == 'suspicious') ⚠️ Mencurigakan
                        @else ❌ Berbahaya
                        @endif
                    </div>
                </div>

                <!-- Stats Summary -->
                <div class="grid grid-cols-2 gap-4">
                    <div class="bg-gray-800/50 p-4 rounded-xl border border-gray-700 text-center">
                        <span class="block text-2xl font-bold text-green-400">{{ $scan->signals->where('impact', 'positive')->count() }}</span>
                        <span class="text-xs text-gray-400 uppercase">Sinyal Positif</span>
                    </div>
                    <div class="bg-gray-800/50 p-4 rounded-xl border border-gray-700 text-center">
                        <span class="block text-2xl font-bold text-red-400">{{ $scan->signals->whereIn('impact', ['critical', 'navative'])->count() }}</span>
                        <span class="text-xs text-gray-400 uppercase">Resiko</span>
                    </div>
                </div>
            </div>

            <!-- Right Column: Signals Detail -->
            <div class="lg:col-span-2 space-y-4">
                <h3 class="text-xl font-bold text-white mb-2 flex items-center gap-2">
                    <svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"></path></svg>
                    Detail Analisis
                </h3>

                @if($scan->signals->isEmpty())
                    <div class="p-6 bg-gray-800 rounded-xl border border-gray-700 text-center text-gray-400">
                        Tidak ada sinyal spesifik yang ditemukan untuk URL ini.
                    </div>
                @else
                    @foreach($scan->signals->sortBy('weight') as $signal)
                    <div class="group flex gap-4 p-4 rounded-xl border transition-all hover:bg-gray-800/80
                        @if($signal->impact == 'positive') bg-green-900/10 border-green-900/30 hover:border-green-500/50
                        @elseif($signal->impact == 'warning') bg-yellow-900/10 border-yellow-900/30 hover:border-yellow-500/50
                        @elseif($signal->impact == 'critical') bg-red-900/10 border-red-900/30 hover:border-red-500/50
                        @else bg-gray-800/40 border-gray-700
                        @endif">
                        
                        <div class="flex-shrink-0 mt-1">
                            @if($signal->impact == 'positive') 
                                <span class="flex items-center justify-center w-8 h-8 rounded-full bg-green-500/20 text-green-400">✓</span>
                            @elseif($signal->impact == 'warning')
                                <span class="flex items-center justify-center w-8 h-8 rounded-full bg-yellow-500/20 text-yellow-400">!</span>
                            @elseif($signal->impact == 'critical')
                                <span class="flex items-center justify-center w-8 h-8 rounded-full bg-red-500/20 text-red-400">✕</span>
                            @else
                                <span class="flex items-center justify-center w-8 h-8 rounded-full bg-gray-500/20 text-gray-400">i</span>
                            @endif
                        </div>
                        
                        <div>
                            <h4 class="text-white font-semibold text-base mb-1">
                                {{ ucwords(str_replace('_', ' ', $signal->type)) }}
                            </h4>
                            <p class="text-gray-400 text-sm leading-relaxed">
                                {{ $signal->description }}
                            </p>
                            <span class="inline-block mt-2 text-xs font-mono px-2 py-1 rounded bg-gray-900 text-gray-500">
                                Weight: {{ $signal->weight > 0 ? '+' : '' }}{{ $signal->weight }}
                            </span>
                        </div>
                    </div>
                    @endforeach
                @endif
            </div>

        </div>
        
        <!-- Disclaimer -->
        <div class="mt-8 pt-6 border-t border-gray-800 text-center">
            <p class="text-xs text-gray-600 max-w-3xl mx-auto">
                <strong>Disclaimer:</strong> AmanGakNih.id menggunakan algoritma otomatis untuk memberikan estimasi skor keamanan. 
                Skor hijau tidak menjamin 100% aman, dan skor merah bisa jadi false positive. 
                Gunakan penilaian pribadi Anda dan jangan pernah memasukkan kredensial sensitif di website yang Anda ragukan.
            </p>
        </div>
    </div>
@endif

@endsection