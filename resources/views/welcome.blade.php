@extends('layout')

@section('content')
    <section class="text-center py-20 px-4">
        <div class="max-w-3xl mx-auto space-y-6 animate-fade-in relative z-10">

            <!-- Badge -->
            <span
                class="bg-blue-900/50 text-blue-300 text-xs font-medium inline-flex items-center px-2.5 py-0.5 rounded border border-blue-800 mb-4">
                <svg class="w-2.5 h-2.5 me-1.5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor"
                    viewBox="0 0 20 20">
                    <path
                        d="M10 0a10 10 0 1 0 10 10A10.011 10.011 0 0 0 10 0Zm3.982 13.982a1 1 0 0 1-1.414 0l-3.274-3.274A1.012 1.012 0 0 1 9 10V6a1 1 0 0 1 2 0v3.586l2.982 2.982a1 1 0 0 1 0 1.414Z" />
                </svg>
                Real-time Phishing Detection
            </span>

            <!-- Hero Title -->
            <h1 class="text-5xl md:text-6xl font-extrabold tracking-tight text-white mb-4">
                Cek Keamanan <span
                    class="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-green-400">Website</span>
                <br>Sebelum Anda Klik.
            </h1>

            <p class="text-lg text-gray-400 max-w-2xl mx-auto mb-10">
                Analisis risiko penipuan, phishing, dan keamanan SSL dengan teknologi pemindaian cerdas. Gratis untuk semua
                orang.
            </p>

            <!-- Search Box -->
            <div class="relative max-w-2xl mx-auto">
                <div
                    class="absolute -inset-1 bg-gradient-to-r from-blue-600 to-green-600 rounded-lg blur opacity-40 animate-pulse transition duration-1000 group-hover:opacity-100 duration-200">
                </div>

                <form action="{{ route('scan.store') }}" method="POST"
                    class="relative bg-gray-900 rounded-lg p-2 flex items-center shadow-xl border border-gray-700">
                    @csrf
                    <div class="flex-grow">
                        <div class="absolute inset-y-0 start-0 flex items-center ps-4 pointer-events-none">
                            <svg class="w-5 h-5 text-gray-400" aria-hidden="true" xmlns="http://www.w3.org/2000/svg"
                                fill="none" viewBox="0 0 20 20">
                                <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                    d="m19 19-4-4m0-7A7 7 0 1 1 1 8a7 7 0 0 1 14 0Z" />
                            </svg>
                        </div>
                        <input type="text" name="url"
                            class="block w-full p-4 ps-12 text-md text-white bg-transparent border-none focus:ring-0 placeholder-gray-500"
                            placeholder="Tempel URL di sini (contoh: https://tokopedia-promo.com)" required
                            autocomplete="off" value="{{ old('url') }}">
                    </div>
                    <button type="submit"
                        class="text-white bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg text-sm px-6 py-3 ml-2 transition-all">
                        Analisis
                    </button>
                </form>
            </div>

            @error('url')
                <p class="mt-2 text-sm text-red-500">{{ $message }}</p>
            @enderror

            <!-- Features Grid (Mini) -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-12 text-center text-sm text-gray-400">
                <div class="flex flex-col items-center">
                    <span class="p-2 rounded-full bg-gray-800 mb-2">🔒</span>
                    SSL Checker
                </div>
                <div class="flex flex-col items-center">
                    <span class="p-2 rounded-full bg-gray-800 mb-2">🕵️</span>
                    Whois Age
                </div>
                <div class="flex flex-col items-center">
                    <span class="p-2 rounded-full bg-gray-800 mb-2">🚫</span>
                    Phishing Detect
                </div>
                <div class="flex flex-col items-center">
                    <span class="p-2 rounded-full bg-gray-800 mb-2">🏢</span>
                    Brand Match
                </div>
            </div>

            <!-- Recent Scans -->
            @if($recentScans->isNotEmpty())
                <div class="mt-16 text-left max-w-4xl mx-auto">
                    <h3 class="text-xl font-semibold text-gray-300 mb-4 flex items-center">
                        <svg class="w-5 h-5 me-2 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        Terakhir Dipindai
                    </h3>

                    <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                        @foreach($recentScans as $scan)
                            <a href="{{ route('scan.show', $scan->id) }}"
                                class="block p-4 bg-gray-800/50 rounded-lg border border-gray-700 hover:bg-gray-800 transition group">
                                <div class="flex justify-between items-start mb-2">
                                    <span class="bg-gray-700 text-gray-300 text-xs font-medium px-2 py-0.5 rounded">
                                        {{ $scan->created_at->diffForHumans() }}
                                    </span>
                                    @if($scan->risk_level == 'safe')
                                        <span class="w-3 h-3 rounded-full bg-green-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]"></span>
                                    @elseif($scan->risk_level == 'suspicious')
                                        <span class="w-3 h-3 rounded-full bg-yellow-500 shadow-[0_0_10px_rgba(245,158,11,0.5)]"></span>
                                    @else
                                        <span class="w-3 h-3 rounded-full bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]"></span>
                                    @endif
                                </div>
                                <div class="truncate text-gray-300 font-medium group-hover:text-white transition">
                                    {{ parse_url($scan->normalized_url, PHP_URL_HOST) }}
                                </div>
                                <div class="text-xs text-gray-500 mt-1 truncate">
                                    {{ $scan->normalized_url }}
                                </div>
                            </a>
                        @endforeach
                    </div>
                </div>
            @endif

        </div>
    </section>
@endsection