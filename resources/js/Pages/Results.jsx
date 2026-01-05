import React, { useEffect, useState } from 'react';
import { usePage, router, Link } from '@inertiajs/react';
import Layout from './Layout';
import { motion } from 'framer-motion';

export default function Results({ scan }) {
    const [activeTab, setActiveTab] = useState('overview');

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
    const negativeSignals = scan.signals.filter(s => ['critical', 'warning'].includes(s.impact)).length;

    // Find detailed VT data for Security Tab
    const vtUrlSignal = scan.signals.find(s => s.type.startsWith('vt_url'));
    const vtDomainSignal = scan.signals.find(s => s.type.startsWith('vt_domain'));
    const vendors = vtUrlSignal?.meta_data?.vendors || {};

    // Gauge Logic
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
                        <div className="flex items-center gap-3">
                            <h1 className="text-2xl md:text-3xl font-bold text-white break-all">
                                {host}
                            </h1>
                            {scan.risk_level === 'safe' && <span className="px-3 py-1 bg-green-500/20 text-green-400 text-xs font-bold rounded-full border border-green-500/30">AMAN</span>}
                            {scan.risk_level === 'dangerous' && <span className="px-3 py-1 bg-red-500/20 text-red-400 text-xs font-bold rounded-full border border-red-500/30">BERBAHAYA</span>}
                        </div>
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

                {/* Tabs */}
                <div className="flex justify-center mb-6">
                    <div className="flex p-1 bg-gray-800/50 rounded-xl border border-gray-700">
                        {['overview', 'security', 'domain'].map((tab) => (
                            <button
                                key={tab}
                                onClick={() => setActiveTab(tab)}
                                className={`px-8 py-2.5 rounded-lg text-sm font-medium transition-all min-w-[120px] ${activeTab === tab
                                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/40 transform scale-105'
                                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                                    }`}
                            >
                                {tab.charAt(0).toUpperCase() + tab.slice(1)}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* Left Column: Gauge (Sticky) */}
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

                            <div className="grid grid-cols-2 gap-4 mt-8">
                                <div className="bg-green-500/10 p-3 rounded-lg border border-green-500/10">
                                    <span className="block text-2xl font-bold text-green-400">{positiveSignals}</span>
                                    <span className="text-[10px] text-green-400/60 uppercase font-bold tracking-wider">Aman</span>
                                </div>
                                <div className="bg-red-500/10 p-3 rounded-lg border border-red-500/10">
                                    <span className="block text-2xl font-bold text-red-400">{negativeSignals}</span>
                                    <span className="text-[10px] text-red-400/60 uppercase font-bold tracking-wider">Resiko</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Right Column: Tab Content */}
                    <div className="lg:col-span-2 space-y-4">

                        {activeTab === 'overview' && (
                            <div className="space-y-4">
                                {scan.signals.length === 0 ? (
                                    <div className="p-8 text-center text-gray-500 bg-gray-800 rounded-xl border border-gray-700">Tidak ada sinyal.</div>
                                ) : (
                                    scan.signals.sort((a, b) => b.weight - a.weight).map((signal, idx) => (
                                        <motion.div
                                            key={idx}
                                            initial={{ opacity: 0, y: 10 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            transition={{ delay: idx * 0.05 }}
                                            className={`flex items-start gap-4 p-4 rounded-xl border ${signal.impact === 'critical' ? 'bg-red-900/10 border-red-500/20' :
                                                signal.impact === 'warning' ? 'bg-yellow-900/10 border-yellow-500/20' :
                                                    signal.impact === 'positive' ? 'bg-green-900/10 border-green-500/20' :
                                                        'bg-gray-800 border-gray-700'
                                                }`}
                                        >
                                            <div className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${signal.impact === 'critical' ? 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]' :
                                                signal.impact === 'warning' ? 'bg-yellow-500' : 'bg-green-500'
                                                }`} />
                                            <div>
                                                <h4 className="text-white font-medium text-sm">{signal.type.replace(/_/g, ' ').toUpperCase()}</h4>
                                                <p className="text-gray-400 text-sm mt-1">{signal.description}</p>
                                            </div>
                                        </motion.div>
                                    ))
                                )}
                            </div>
                        )}

                        {activeTab === 'security' && (
                            <div className="bg-gray-800/50 rounded-2xl border border-gray-700 p-6">
                                <h3 className="text-white font-bold mb-4 flex items-center gap-2">
                                    <span>🛡️</span> Security Vendors (VirusTotal)
                                </h3>
                                {Object.keys(vendors).length > 0 ? (
                                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                                        {Object.entries(vendors).map(([vendor, result]) => (
                                            <div key={vendor} className="flex items-center justify-between bg-gray-900/50 p-2 px-3 rounded text-xs border border-gray-700/50">
                                                <span className="text-gray-300 truncate max-w-[100px]">{vendor}</span>
                                                <span className={`font-bold ${result.category === 'malicious' ? 'text-red-400' :
                                                    result.category === 'suspicious' ? 'text-yellow-400' : 'text-green-400'
                                                    }`}>
                                                    {result.result === 'clean' ? 'Safe' : result.result}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                ) : (
                                    <div className="text-center py-10 text-gray-500">
                                        <p>Data vendor keamanan tidak tersedia atau belum dipindai sepenuhnya.</p>
                                    </div>
                                )}
                            </div>
                        )}

                        {activeTab === 'domain' && (
                            <div className="bg-gray-800/50 rounded-2xl border border-gray-700 p-6 space-y-6">
                                <div>
                                    <h3 className="text-white font-bold mb-2">Domain Stats</h3>
                                    {vtDomainSignal?.meta_data ? (
                                        <div className="grid grid-cols-2 gap-4 text-sm">
                                            <div className="bg-gray-900 p-3 rounded border border-gray-700">
                                                <span className="text-gray-500 block">Creation Date</span>
                                                <span className="text-white">
                                                    {vtDomainSignal.meta_data.creation_date
                                                        ? new Date(vtDomainSignal.meta_data.creation_date * 1000).toLocaleDateString()
                                                        : 'Unknown'
                                                    }
                                                </span>
                                            </div>
                                            <div className="bg-gray-900 p-3 rounded border border-gray-700">
                                                <span className="text-gray-500 block">Categories</span>
                                                <span className="text-white">
                                                    {Object.keys(vtDomainSignal.meta_data.categories || {}).join(', ') || 'Uncategorized'}
                                                </span>
                                            </div>
                                        </div>
                                    ) : (
                                        <p className="text-gray-500 text-sm">Data domain detail tidak ditemukan.</p>
                                    )}
                                </div>
                            </div>
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
