import React, { useEffect } from 'react';
import { usePage, router, Link } from '@inertiajs/react';
import Layout from './Layout';
import { motion } from 'framer-motion';

export default function Results({ scan }) {

    // Auto-refresh mechanism for pending scans
    useEffect(() => {
        if (scan.status !== 'completed' && scan.status !== 'failed') {
            const interval = setInterval(() => {
                router.reload({
                    data: { _t: Date.now() },
                    preserveScroll: true
                });
            }, 3000);
            return () => clearInterval(interval);
        }
    }, [scan.status]);

    if (scan.status !== 'completed' && scan.status !== 'failed') {
        return (
            <Layout>
                <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
                    <div className="relative w-24 h-24 mb-8">
                        <div className="absolute inset-0 border-4 border-blue-500/30 rounded-full animate-ping"></div>
                        <div className="absolute inset-0 border-4 border-t-blue-500 border-r-transparent border-b-transparent border-l-transparent rounded-full animate-spin"></div>
                        <div className="absolute inset-2 bg-gray-800 rounded-full flex items-center justify-center">
                            <span className="text-3xl">🔍</span>
                        </div>
                    </div>
                    <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-green-400 mb-4">
                        Sedang Menganalisis...
                    </h2>
                    <p className="text-gray-400 max-w-md mx-auto mb-4">
                        Kami sedang memindai domain, sertifikat SSL, dan pola keamanan lainnya. Mohon tunggu sebentar.
                    </p>
                </div>
            </Layout>
        );
    }

    const host = new URL(scan.normalized_url).hostname;
    const positiveSignals = scan.signals.filter(s => s.impact === 'positive').length;
    const negativeSignals = scan.signals.filter(s => ['critical', 'navative'].includes(s.impact)).length;

    // Determine Gauge Color
    let gaugeColor = "text-red-500";
    if (scan.risk_level === 'safe') gaugeColor = "text-green-500";
    if (scan.risk_level === 'suspicious') gaugeColor = "text-yellow-500";

    // Gauge calculation
    const radius = 90;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (scan.final_score / 100) * circumference;


    return (
        <Layout>
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-6"
            >
                {/* Header */}
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-gray-800/50 p-6 rounded-2xl border border-gray-700 backdrop-blur-sm">
                    <div>
                        <h1 className="text-2xl md:text-3xl font-bold text-white break-all">
                            {host}
                        </h1>
                        <p className="text-gray-400 text-sm mt-1">{scan.normalized_url}</p>
                        <p className="text-gray-500 text-xs mt-2">ID Scan: #{scan.id} • {new Date(scan.created_at).toLocaleString()}</p>
                    </div>
                    <div className="flex gap-3">
                        <Link href="/" className="px-5 py-2.5 text-sm font-medium text-white bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                            Scan Baru
                        </Link>
                        <button onClick={() => window.print()} className="px-5 py-2.5 text-sm font-medium text-gray-900 bg-white hover:bg-gray-100 rounded-lg transition-colors">
                            Cetak Laporan
                        </button>
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* Left Column: Score & Summary */}
                    <div className="lg:col-span-1 space-y-6">
                        {/* Score Card */}
                        <div className="bg-gray-800/80 p-8 rounded-2xl border border-gray-700 text-center relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-green-500"></div>

                            <h3 className="text-gray-400 font-medium uppercase tracking-wider text-sm mb-6">Trust Score</h3>

                            <div className="relative w-48 h-48 mx-auto mb-6 flex items-center justify-center">
                                {/* SVG Gauge */}
                                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 200 200">
                                    <circle cx="100" cy="100" r={radius} stroke="currentColor" strokeWidth="12" fill="transparent" className="text-gray-700" />
                                    <motion.circle
                                        initial={{ strokeDashoffset: circumference }}
                                        animate={{ strokeDashoffset: offset }}
                                        transition={{ duration: 1.5, ease: "easeOut" }}
                                        cx="100" cy="100" r={radius}
                                        stroke="currentColor" strokeWidth="12" fill="transparent"
                                        strokeDasharray={circumference}
                                        strokeDashoffset={offset}
                                        strokeLinecap="round"
                                        className={gaugeColor}
                                    />
                                </svg>

                                <div className="absolute inset-0 flex flex-col items-center justify-center">
                                    <span className="text-6xl font-extrabold text-white">{scan.final_score}</span>
                                    <span className="text-sm text-gray-500">/ 100</span>
                                </div>
                            </div>

                            <div className={`inline-block px-6 py-2 rounded-full font-bold text-lg uppercase tracking-wide border
                                ${scan.risk_level === 'safe' ? 'bg-green-500/10 text-green-400 border-green-500/20' : ''}
                                ${scan.risk_level === 'suspicious' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' : ''}
                                ${scan.risk_level === 'dangerous' ? 'bg-red-500/10 text-red-500 border-red-500/20' : ''}
                            `}>
                                {scan.risk_level === 'safe' && '✅ Relatif Aman'}
                                {scan.risk_level === 'suspicious' && '⚠️ Mencurigakan'}
                                {scan.risk_level === 'dangerous' && '❌ Berbahaya'}
                            </div>
                        </div>

                        {/* Stats Summary */}
                        <div className="grid grid-cols-2 gap-4">
                            <div className="bg-gray-800/50 p-4 rounded-xl border border-gray-700 text-center">
                                <span className="block text-2xl font-bold text-green-400">{positiveSignals}</span>
                                <span className="text-xs text-gray-400 uppercase">Sinyal Positif</span>
                            </div>
                            <div className="bg-gray-800/50 p-4 rounded-xl border border-gray-700 text-center">
                                <span className="block text-2xl font-bold text-red-400">{negativeSignals}</span>
                                <span className="text-xs text-gray-400 uppercase">Resiko</span>
                            </div>
                        </div>
                    </div>

                    {/* Right Column: Signals Detail */}
                    <div className="lg:col-span-2 space-y-4">
                        <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
                            Detail Analisis
                        </h3>

                        {scan.signals.length === 0 ? (
                            <div className="p-6 bg-gray-800 rounded-xl border border-gray-700 text-center text-gray-400">
                                Tidak ada sinyal spesifik yang ditemukan untuk URL ini.
                            </div>
                        ) : (
                            scan.signals
                                .sort((a, b) => b.weight - a.weight) // Sort desc by absolute weight (simplified)
                                .map((signal, index) => (
                                    <motion.div
                                        key={signal.id}
                                        initial={{ opacity: 0, x: 20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: index * 0.1 }}
                                        className={`group flex gap-4 p-4 rounded-xl border transition-all hover:bg-gray-800/80
                                        ${signal.impact === 'positive' ? 'bg-green-900/10 border-green-900/30 hover:border-green-500/50' : ''}
                                        ${signal.impact === 'warning' ? 'bg-yellow-900/10 border-yellow-900/30 hover:border-yellow-500/50' : ''}
                                        ${signal.impact === 'critical' ? 'bg-red-900/10 border-red-900/30 hover:border-red-500/50' : ''}
                                        ${!['positive', 'warning', 'critical'].includes(signal.impact) ? 'bg-gray-800/40 border-gray-700' : ''}
                                    `}
                                    >
                                        <div className="flex-shrink-0 mt-1">
                                            {signal.impact === 'positive' && <span className="flex items-center justify-center w-8 h-8 rounded-full bg-green-500/20 text-green-400">✓</span>}
                                            {signal.impact === 'warning' && <span className="flex items-center justify-center w-8 h-8 rounded-full bg-yellow-500/20 text-yellow-400">!</span>}
                                            {signal.impact === 'critical' && <span className="flex items-center justify-center w-8 h-8 rounded-full bg-red-500/20 text-red-400">✕</span>}
                                            {!['positive', 'warning', 'critical'].includes(signal.impact) && <span className="flex items-center justify-center w-8 h-8 rounded-full bg-gray-500/20 text-gray-400">i</span>}
                                        </div>

                                        <div>
                                            <h4 className="text-white font-semibold text-base mb-1 capitalize">
                                                {signal.type.replace(/_/g, ' ')}
                                            </h4>
                                            <p className="text-gray-400 text-sm leading-relaxed">
                                                {signal.description}
                                            </p>
                                            <span className="inline-block mt-2 text-xs font-mono px-2 py-1 rounded bg-gray-900 text-gray-500">
                                                Weight: {signal.weight > 0 ? '+' : ''}{signal.weight}
                                            </span>
                                        </div>
                                    </motion.div>
                                ))
                        )}
                    </div>

                </div>

                {/* Disclaimer */}
                <div className="mt-8 pt-6 border-t border-gray-800 text-center">
                    <p className="text-xs text-gray-600 max-w-3xl mx-auto">
                        <strong>Disclaimer:</strong> AmanGakNih.id menggunakan algoritma otomatis untuk memberikan estimasi skor keamanan.
                        Skor hijau tidak menjamin 100% aman, dan skor merah bisa jadi false positive.
                        Gunakan penilaian pribadi Anda dan jangan pernah memasukkan kredensial sensitif di website yang Anda ragukan.
                    </p>
                </div>
            </motion.div>
        </Layout>
    );
}

