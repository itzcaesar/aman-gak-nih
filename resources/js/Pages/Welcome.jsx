import React from 'react';
import { useForm, Link } from '@inertiajs/react';
import { motion } from 'framer-motion';
import Layout from './Layout';

export default function Welcome() {
    const { data, setData, post, processing, errors } = useForm({
        url: '',
    });

    const handleSubmit = (e) => {
        e.preventDefault();
        post('/scan');
    };

    return (
        <Layout>
            <section className="text-center py-20 px-4">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8 }}
                    className="max-w-3xl mx-auto space-y-6 relative z-10"
                >
                    {/* Badge */}
                    <span className="bg-blue-900/50 text-blue-300 text-xs font-medium inline-flex items-center px-2.5 py-0.5 rounded border border-blue-800 mb-4">
                        <svg className="w-2.5 h-2.5 me-1.5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                            <path d="M10 0a10 10 0 1 0 10 10A10.011 10.011 0 0 0 10 0Zm3.982 13.982a1 1 0 0 1-1.414 0l-3.274-3.274A1.012 1.012 0 0 1 9 10V6a1 1 0 0 1 2 0v3.586l2.982 2.982a1 1 0 0 1 0 1.414Z" />
                        </svg>
                        Real-time Phishing Detection
                    </span>

                    {/* Hero Title */}
                    <h1 className="text-5xl md:text-6xl font-extrabold tracking-tight text-white mb-4">
                        Cek Keamanan <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-green-400">Website</span>
                        <br />Sebelum Anda Klik.
                    </h1>

                    <p className="text-lg text-gray-400 max-w-2xl mx-auto mb-10">
                        Analisis risiko penipuan, phishing, dan keamanan SSL dengan teknologi pemindaian cerdas. Gratis untuk semua orang.
                    </p>

                    {/* Search Box */}
                    <div className="relative max-w-2xl mx-auto">
                        <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-green-600 rounded-lg blur opacity-40 animate-pulse transition duration-1000 group-hover:opacity-100 duration-200"></div>

                        <form onSubmit={handleSubmit} className="relative bg-gray-900 rounded-lg p-2 flex items-center shadow-xl border border-gray-700">
                            <div className="flex-grow">
                                <div className="absolute inset-y-0 start-0 flex items-center ps-4 pointer-events-none">
                                    <svg className="w-5 h-5 text-gray-400" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 20 20">
                                        <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m19 19-4-4m0-7A7 7 0 1 1 1 8a7 7 0 0 1 14 0Z" />
                                    </svg>
                                </div>
                                <input
                                    type="text"
                                    value={data.url}
                                    onChange={e => setData('url', e.target.value)}
                                    className="block w-full p-4 ps-12 text-md text-white bg-transparent border-none focus:ring-0 placeholder-gray-500 focus:outline-none"
                                    placeholder="Tempel URL di sini (contoh: https://tokopedia-promo.com)"
                                    required
                                    autoComplete="off"
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={processing}
                                className="text-white bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg text-sm px-6 py-3 ml-2 transition-all disabled:opacity-50"
                            >
                                {processing ? 'Menganalisis...' : 'Analisis'}
                            </button>
                        </form>
                    </div>

                    {errors.url && <p className="mt-2 text-sm text-red-500">{errors.url}</p>}

                    {/* Features Grid (Mini) */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-12 text-center text-sm text-gray-400">
                        <div className="flex flex-col items-center">
                            <span className="p-2 rounded-full bg-gray-800 mb-2">🔒</span>
                            SSL Checker
                        </div>
                        <div className="flex flex-col items-center">
                            <span className="p-2 rounded-full bg-gray-800 mb-2">🕵️</span>
                            Whois Age
                        </div>
                        <div className="flex flex-col items-center">
                            <span className="p-2 rounded-full bg-gray-800 mb-2">🚫</span>
                            Phishing Detect
                        </div>
                        <div className="flex flex-col items-center">
                            <span className="p-2 rounded-full bg-gray-800 mb-2">🏢</span>
                            Brand Match
                        </div>
                    </div>
                </motion.div>
            </section>
        </Layout>
    );
}
