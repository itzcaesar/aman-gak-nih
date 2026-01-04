<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}" class="dark">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('title', 'amangaknih.id - Cek Keamanan Website')</title>

    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">

    <!-- Vite -->
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>

<body class="bg-gray-900 text-white min-h-screen flex flex-col font-body">

    <!-- Navbar -->
    <nav class="bg-gray-900/80 backdrop-blur-md fixed w-full z-20 top-0 start-0 border-b border-gray-800">
        <div class="max-w-screen-xl flex flex-wrap items-center justify-between mx-auto p-4">
            <a href="{{ route('home') }}" class="flex items-center space-x-3 rtl:space-x-reverse">
                <div
                    class="w-10 h-10 bg-gradient-to-br from-primary-600 to-green-500 rounded-lg flex items-center justify-center text-xl shadow-lg">
                    🛡️</div>
                <span
                    class="self-center text-2xl font-bold whitespace-nowrap bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-green-400">amangaknih.id</span>
            </a>
            <div class="flex md:order-2 space-x-3 md:space-x-0 rtl:space-x-reverse">
                <a href="https://github.com/itzcaesar/aman-gak-nih" target="_blank"
                    class="text-white bg-gray-800 hover:bg-gray-700 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-4 py-2 text-center transition-all border border-gray-700">
                    GitHub Repo
                </a>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="flex-grow pt-24 pb-12 px-4">
        <div class="max-w-screen-xl mx-auto">
            @yield('content')
        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-gray-900 border-t border-gray-800 mt-auto">
        <div class="w-full max-w-screen-xl mx-auto p-4 md:py-8">
            <div class="sm:flex sm:items-center sm:justify-between">
                <a href="{{ route('home') }}" class="flex items-center mb-4 sm:mb-0 space-x-3 rtl:space-x-reverse">
                    <span class="self-center text-xl font-semibold whitespace-nowrap text-gray-400">amangaknih.id</span>
                </a>
                <ul class="flex flex-wrap items-center mb-6 text-sm font-medium text-gray-400 sm:mb-0">
                    <li>
                        <a href="https://github.com/itzcaesar/aman-gak-nih" class="hover:underline me-4 md:me-6">Tentang
                            Project</a>
                    </li>
                    <li>
                        <a href="#" class="hover:underline">Privacy Policy</a>
                    </li>
                </ul>
            </div>
            <hr class="my-6 border-gray-700 sm:mx-auto lg:my-8" />
            <span class="block text-sm text-gray-500 sm:text-center">© {{ date('Y') }} AmanGakNih.id. Open Source
                Project.</span>
        </div>
    </footer>

</body>

</html>