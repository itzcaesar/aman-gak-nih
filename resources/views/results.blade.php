@extends('layout')

@section('content')

    @if($scan->status !== 'completed' && $scan->status !== 'failed')
        <div class="glass-card animate-fade-in" style="text-align: center; padding: 4rem 2rem;">
            <div class="spinner"></div>
            <h2 style="margin-top: 2rem;">Sedang Menganalisis...</h2>
            <p style="color: var(--text-muted);">Mohon tunggu sebentar, kami sedang mengecek keamanan URL ini.</p>

            <script>
                setTimeout(function () {
                    window.location.reload();
                }, 2000);
            </script>
        </div>
    @else
        <div class="glass-card animate-fade-in">
            <div style="text-align: center;">
                <div class="score-circle {{ $scan->risk_level }}">
                    {{ $scan->final_score }}
                </div>

                <div class="risk-badge {{ $scan->risk_level }}">
                    @if($scan->risk_level == 'safe') ✅ Relatif Aman
                    @elseif($scan->risk_level == 'suspicious') ⚠️ Mencurigakan
                    @else ❌ Berbahaya
                    @endif
                </div>

                <h3 style="word-break: break-all; margin-bottom: 2rem;">{{ $scan->normalized_url }}</h3>
            </div>

            <div style="margin-top: 2rem;">
                <h3>📋 Hasil Analisis</h3>

                @if($scan->signals->isEmpty())
                    <p style="text-align: center; color: var(--text-muted);">Tidak ada sinyal spesifik yang ditemukan.</p>
                @else
                    <ul class="signal-list">
                        @foreach($scan->signals->sortBy('weight') as $signal)
                            <li class="signal-item {{ $signal->impact }}">
                                <div class="signal-icon">
                                    @if($signal->impact == 'positive') ✅
                                    @elseif($signal->impact == 'warning') ⚠️
                                    @elseif($signal->impact == 'critical') ❌
                                    @else ℹ️
                                    @endif
                                </div>
                                <div class="signal-content">
                                    <h4>{{ ucwords(str_replace('_', ' ', $signal->type)) }}</h4>
                                    <p>{{ $signal->description }}</p>
                                </div>
                            </li>
                        @endforeach
                    </ul>
                @endif
            </div>

            <div style="margin-top: 3rem; text-align: center;">
                <a href="{{ route('home') }}" class="btn-primary"
                    style="text-decoration: none; display: inline-block; width: auto; padding: 0.75rem 2rem;">
                    Cek Website Lain
                </a>

                <p
                    style="margin-top: 2rem; border-top: 1px solid var(--glass-border); padding-top: 1rem; font-size: 0.8rem; color: var(--text-muted);">
                    <strong>Disclaimer:</strong> Skor ini adalah estimasi otomatis berdasarkan sinyal teknis. Skor tinggi tidak
                    menjamin keamanan 100%. Jangan pernah masukkan data sensitif jika Anda ragu.
                </p>
            </div>
        </div>
    @endif

@endsection