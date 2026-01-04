<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('title', 'amangaknih.id - Cek Keamanan Website')</title>

    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">

    <!-- CSS -->
    <link rel="stylesheet" href="{{ asset('css/style.css') }}">
</head>

<body>
    <div class="container animate-fade-in">
        <header>
            <h1>amangaknih.id</h1>
            <p style="text-align: center; color: var(--text-muted); margin-top: -1.5rem; margin-bottom: 2rem;">
                Cek risiko phishing & scam sebelum Anda klik via web ini.
            </p>
        </header>

        <main>
            @yield('content')
        </main>

        <footer style="text-align: center; margin-top: 3rem; color: var(--text-muted); font-size: 0.8rem;">
            <p>&copy; {{ date('Y') }} AmanGakNih.id. Tidak ada jaminan 100% aman.</p>
        </footer>
    </div>
</body>

</html>