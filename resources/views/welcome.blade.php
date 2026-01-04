@extends('layout')

@section('content')
    <div class="glass-card animate-fade-in" style="margin-top: 4rem;">
        <form action="{{ route('scan.store') }}" method="POST">
            @csrf

            <div class="input-group">
                <h2 style="text-align: center; margin-bottom: 2rem; color: var(--text-main);">
                    Tempel URL Website
                </h2>

                <input type="text" name="url" placeholder="https://contoh-website.com" required value="{{ old('url') }}"
                    autocomplete="off">
                @error('url')
                    <div style="color: var(--danger); margin-top: 0.5rem; font-size: 0.9rem;">
                        {{ $message }}
                    </div>
                @enderror
            </div>

            <button type="submit" class="btn-primary pulsate">
                Analisis Sekarang
            </button>
        </form>

        <div style="margin-top: 2rem; text-align: center;">
            <p style="color: var(--text-muted); font-size: 0.9rem;">
                🔍 Mengecek Domain, SSL, Pola URL, & Impersonasi Brand
            </p>
        </div>
    </div>
@endsection