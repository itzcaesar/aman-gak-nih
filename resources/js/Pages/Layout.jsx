import React from 'react';
import { Link } from '@inertiajs/react';

export default function Layout({ children }) {
    return (
        <div className="min-h-screen flex flex-col font-body bg-gray-900 text-white selection:bg-blue-500 selection:text-white">

            {/* Navbar */}
            <nav className="bg-gray-900/80 backdrop-blur-md fixed w-full z-20 top-0 start-0 border-b border-gray-800">
                <div className="max-w-screen-xl flex flex-wrap items-center justify-between mx-auto p-4">
                    <Link href="/" className="flex items-center space-x-3 rtl:space-x-reverse">
                        <div className="w-10 h-10 bg-gradient-to-br from-primary-600 to-green-500 rounded-lg flex items-center justify-center text-xl shadow-lg">🛡️</div>
                        <span className="self-center text-2xl font-bold whitespace-nowrap bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-green-400">amangaknih.id</span>
                    </Link>
                    <div className="flex md:order-2 space-x-3 md:space-x-0 rtl:space-x-reverse">
                        <a href="https://github.com/itzcaesar/aman-gak-nih" target="_blank" className="text-white bg-gray-800 hover:bg-gray-700 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-4 py-2 text-center transition-all border border-gray-700">
                            GitHub Repo
                        </a>
                    </div>
                </div>
            </nav>

            {/* Main Content */}
            <main className="flex-grow pt-24 pb-12 px-4">
                <div className="max-w-screen-xl mx-auto">
                    {children}
                </div>
            </main>

            {/* Footer */}
            <footer className="bg-gray-900 border-t border-gray-800 mt-auto">
                <div className="w-full max-w-screen-xl mx-auto p-4 md:py-8">
                    <div className="sm:flex sm:items-center sm:justify-between">
                        <Link href="/" className="flex items-center mb-4 sm:mb-0 space-x-3 rtl:space-x-reverse">
                            <span className="self-center text-xl font-semibold whitespace-nowrap text-gray-400">amangaknih.id</span>
                        </Link>
                        <ul className="flex flex-wrap items-center mb-6 text-sm font-medium text-gray-400 sm:mb-0">
                            <li>
                                <a href="https://github.com/itzcaesar/aman-gak-nih" className="hover:underline me-4 md:me-6">Tentang Project</a>
                            </li>
                            <li>
                                <a href="#" className="hover:underline">Privacy Policy</a>
                            </li>
                        </ul>
                    </div>
                    <hr className="my-6 border-gray-700 sm:mx-auto lg:my-8" />
                    <span className="block text-sm text-gray-500 sm:text-center">© {new Date().getFullYear()} AmanGakNih.id. Open Source Project.</span>
                </div>
            </footer>
        </div>
    );
}
