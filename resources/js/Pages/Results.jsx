import React, { useEffect, useState } from 'react';
import { usePage, router, Link } from '@inertiajs/react';
import { motion } from 'framer-motion';
import MatrixRain from '../Components/MatrixRain';

export default function Results({ scan }) {
    const [activeTab, setActiveTab] = useState('overview');
    const [vtTab, setVtTab] = useState('detection');

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

    // Loading View
    if (scan.status !== 'completed' && scan.status !== 'failed') {
        return (
            <div className="min-h-screen bg-[#0a0a0a] text-white font-sans flex flex-col items-center justify-center relative overflow-hidden">
                <MatrixRain />
                <div className="relative z-10 text-center px-4">
                    <div className="relative w-32 h-32 mx-auto mb-8">
                        <div className="absolute inset-0 border-4 border-blue-600/30 rounded-full animate-ping"></div>
                        <div className="absolute inset-0 border-4 border-t-blue-500 border-r-transparent border-b-transparent border-l-transparent rounded-full animate-spin"></div>
                        <div className="absolute inset-2 bg-[#0a0a0a] rounded-full flex items-center justify-center border border-blue-500/20 shadow-[0_0_40px_rgba(37,99,235,0.2)]">
                            <span className="text-4xl animate-pulse">🛡️</span>
                        </div>
                    </div>
                    <h2 className="text-2xl font-bold text-white mb-2 tracking-widest uppercase font-mono">Initializing Deep Scan</h2>
                    <p className="text-blue-400/60 font-mono text-xs uppercase tracking-wider"> querying cyber-intelligence databases...</p>
                </div>
            </div>
        );
    }

    // Analysis Data
    const host = new URL(scan.normalized_url).hostname;
    const positiveSignals = scan.signals.filter(s => s.impact === 'positive').length;
    const negativeSignals = scan.signals.filter(s => ['critical', 'warning'].includes(s.impact)).length;

    // Correctly finding VT data - prioritizing signals that have actual data
    const vtUrlSignal = scan.signals.find(s => s.type.includes('vt_url'));

    const domainSignals = scan.signals.filter(s => s.type.includes('domain') || s.type.includes('whois'));
    // Prioritize a signal that actually has creation_date (e.g. from VT or API Ninja if successful)
    // Fallback to the first one found if none have data
    const vtDomainSignal = domainSignals.find(s => s.meta_data && s.meta_data.creation_date) || domainSignals[0];

    // Fallback emptiness
    const domainData = vtUrlSignal?.meta_data?.domain_info || vtDomainSignal?.meta_data || {};
    const dnsRecords = domainData.last_dns_records || [];
    const sslCert = domainData.last_https_certificate || null;
    const jarm = domainData.jarm || null;
    const popularity = domainData.popularity_ranks || {};
    const whoisData = domainData.whois || null;
    const registrar = domainData.registrar || null;
    const creationDate = domainData.creation_date || null;

    // Fallback emptiness
    const vtData = vtUrlSignal?.meta_data || {};
    const vendors = vtData.vendors || {};
    const httpInfo = vtData.http_response || {};
    const htmlInfo = vtData.html_info || {};

    // Use URL votes if available, otherwise domain votes (often URL specific votes are 0)
    const votes = (vtData.votes && (vtData.votes.harmless > 0 || vtData.votes.malicious > 0))
        ? vtData.votes
        : (domainData.votes || vtData.votes || {});

    const submission = vtData.submission || {};

    // GSB Data
    const gsbSignal = scan.signals.find(s => s.type.includes('google_safe_browsing'));
    const gsbData = gsbSignal?.meta_data || {};
    const gsbThreats = gsbData.checked_threat_types || [];

    // Trust Score Gauge
    let gaugeColor = "text-red-500";
    if (scan.risk_level === 'safe') gaugeColor = "text-green-500";
    if (scan.risk_level === 'suspicious') gaugeColor = "text-yellow-500";

    const radius = 80;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (scan.final_score / 100) * circumference;

    return (
        <div className="min-h-screen text-white font-sans selection:bg-blue-500/30 flex flex-col relative overflow-x-hidden print:bg-white print:text-black print:min-h-0 print:overflow-visible">
            <MatrixRain />

            <style>{`
                @media print {
                    @page { margin: 15mm; size: A4; }
                    * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
                    body, html, #app { background-color: white !important; background: white !important; color: black !important; width: 100%; height: auto; overflow: visible; }
                    .no-print, nav, .web-main, button, .tabs-container { display: none !important; }
                    
                    /* Force display block for print container */
                    .print-container { display: block !important; visibility: visible !important; opacity: 1 !important; width: 100%; position: static; }
                    
                    /* Typography overrides */
                    .print-container div, .print-container span, .print-container p, .print-container h1, .print-container h2, .print-container h3 {
                        color: black !important;
                        text-shadow: none !important;
                    }
                    
                    /* Utility overrides */
                    .text-white { color: black !important; }
                    .text-gray-400, .text-gray-500, .text-gray-600 { color: #333 !important; }
                    .bg-black, .bg-[#0a0a0a] { background-color: white !important; }
                    .border-white\/5, .border-white\/10 { border-color: #ddd !important; }
                    
                    /* Specific table/grid fixes */
                    .finding-row { break-inside: avoid; page-break-inside: avoid; }
                    
                    /* Hide web background elements */
                    .absolute.inset-0 { display: none !important; }
                }
                .print-container { display: none; }
            `}</style>

            {/* PRINT VIEW */}
            <div className="print-container font-mono bg-white text-black p-8 max-w-[210mm] mx-auto">
                {/* Header */}
                <div className="border-b-4 border-black pb-6 mb-8 flex justify-between items-end">
                    <div>
                        <h1 className="text-4xl font-black uppercase tracking-widest leading-none mb-2">Security<br />Report</h1>
                        <p className="text-xs uppercase tracking-widest text-gray-600">Amangaknih.id Intelligence Unit</p>
                    </div>
                    <div className="text-right text-[10px] leading-tight text-gray-800">
                        <p><strong>SCAN ID:</strong> #{scan.id}</p>
                        <p><strong>DATE:</strong> {new Date().toLocaleDateString().toUpperCase()}</p>
                        <p><strong>TARGET:</strong> {host}</p>
                    </div>
                </div>

                {/* Executive Summary */}
                <div className="mb-8">
                    <h3 className="text-xs font-bold uppercase border-b-2 border-black mb-3 pb-1">01 // Executive Summary</h3>
                    <div className="bg-gray-100 p-4 border-l-4 border-black text-xs leading-relaxed text-justify text-black">
                        {scan.risk_level === 'safe'
                            ? "The analyzed domain exhibits a LOW RISK profile. All primary security checkpoints—including SSL validity, domain reputation, and threat intelligence feeds—returned negative for malicious indicators. Standard security hygiene is observed."
                            : scan.risk_level === 'suspicious'
                                ? "The analyzed domain exhibits a MODERATE RISK profile. Heuristics detected anomalies consistent with suspicious activity, such as recent registration or mixed vendor reputation. Caution is advised."
                                : "CRITICAL ALERT: The analyzed domain exhibits a HIGH RISK profile. Confirmed malicious signatures or known phishing patterns were detected. Immediate access restriction is recommended."
                        }
                    </div>
                </div>

                {/* Score Dashboard */}
                <div className="grid grid-cols-2 gap-6 mb-8">
                    <div className="border border-black p-6 flex flex-col items-center justify-center">
                        <span className="text-6xl font-black mb-2 text-black">{scan.final_score}</span>
                        <span className="text-[10px] uppercase tracking-widest font-bold">Trust Score</span>
                    </div>
                    <div className="border border-black p-6 relative">
                        <div className="flex justify-between items-center mb-2 border-b border-gray-200 pb-2">
                            <span className="text-[10px] font-bold uppercase">Passed Checks</span>
                            <span className="font-bold text-lg text-black">{positiveSignals}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-[10px] font-bold uppercase">Threats Found</span>
                            <span className="font-bold text-lg text-black">{negativeSignals}</span>
                        </div>
                        <div className="absolute top-0 right-0 bg-black text-white text-[10px] px-2 py-1 uppercase font-bold">
                            {scan.risk_level}
                        </div>
                    </div>
                </div>

                {/* Detailed Findings */}
                <div className="mb-8">
                    <h3 className="text-xs font-bold uppercase border-b-2 border-black mb-3 pb-1">02 // Detailed Analysis Ledger</h3>
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="border-b-2 border-black text-[9px] uppercase">
                                <th className="py-2 w-24">Severity</th>
                                <th className="py-2 w-48">Vector</th>
                                <th className="py-2">Observation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {scan.signals.map((s, i) => (
                                <tr key={i} className="border-b border-gray-200 text-[10px] finding-row">
                                    <td className={`py-2 font-bold uppercase ${s.impact === 'critical' ? 'text-black' : 'text-gray-700'}`}>
                                        {s.impact === 'critical' ? 'CRITICAL' : s.impact}
                                    </td>
                                    <td className="py-2 font-mono text-[9px] uppercase">{s.type.replace(/_/g, ' ')}</td>
                                    <td className="py-2 text-gray-800">{s.description}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Domain Info */}
                <div className="grid grid-cols-2 gap-4 mb-8 text-[10px]">
                    <div>
                        <h4 className="font-bold border-b border-gray-300 mb-2 uppercase">Registrar Information</h4>
                        <p className="font-mono text-gray-800">{domainData.registrar || 'DATA REDACTED'}</p>
                    </div>
                    <div>
                        <h4 className="font-bold border-b border-gray-300 mb-2 uppercase">Creation Date</h4>
                        <p className="font-mono text-gray-800">{domainData.creation_date ? new Date(domainData.creation_date * 1000).toUTCString() : 'UNKNOWN'}</p>
                    </div>
                </div>

                <div className="text-center pt-8 border-t border-gray-300 text-[8px] uppercase text-gray-500">
                    Proprietary Automated Analysis • Generated by AmanGakNih.id • {new Date().getFullYear()}
                </div>
            </div>


            {/* WEB VIEW */}
            <nav className="relative z-50 p-6 w-full border-b border-white/5 bg-[#0a0a0a]/50 backdrop-blur-md no-print">
                <div className="max-w-7xl mx-auto flex justify-between items-center">
                    <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
                        <div className="w-10 h-10 bg-blue-900/30 border border-blue-500/50 flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)]">
                            <span className="text-xl">🛡️</span>
                        </div>
                        <span className="text-xl font-bold tracking-tight text-white uppercase font-mono">
                            amangaknih.id
                        </span>
                    </Link>
                    <a href="https://github.com/itzcaesar/aman-gak-nih" className="text-sm font-bold text-gray-400 hover:text-white transition-colors border border-white/10 px-4 py-2 hover:bg-white/5 uppercase tracking-wider font-mono">
                        GitHub
                    </a>
                </div>
            </nav>

            <main className="web-main relative z-10 flex-grow px-4 py-8 md:py-12 max-w-7xl mx-auto w-full no-print">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-8"
                >
                    {/* Main Header Card */}
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 bg-black/80 backdrop-blur-md p-8 rounded-none border-l-4 border-l-blue-600 border-y border-r border-y-white/5 border-r-white/5 shadow-2xl relative overflow-hidden">
                        {/* Mesh grid background pattern */}
                        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none"></div>

                        <div className="relative z-10">
                            <div className="flex items-center gap-4 flex-wrap">
                                <h1 className="text-2xl md:text-3xl font-bold text-white break-all tracking-tight font-mono">
                                    {host}
                                </h1>
                                {scan.risk_level === 'safe' && <span className="px-3 py-1 bg-green-900/20 text-green-400 text-xs font-bold border border-green-500/30 tracking-widest uppercase font-mono">SECURE</span>}
                                {scan.risk_level === 'suspicious' && <span className="px-3 py-1 bg-yellow-900/20 text-yellow-400 text-xs font-bold border border-yellow-500/30 tracking-widest uppercase font-mono">SUSPICIOUS</span>}
                                {scan.risk_level === 'dangerous' && <span className="px-3 py-1 bg-red-900/20 text-red-500 text-xs font-bold border border-red-500/50 tracking-widest uppercase animate-pulse font-mono">DANGEROUS</span>}
                            </div>
                            <p className="text-blue-500/50 text-xs mt-2 font-mono uppercase tracking-wider">{scan.normalized_url}</p>
                        </div>
                        <div className="flex gap-3 w-full md:w-auto relative z-10">
                            <Link href="/" className="px-6 py-3 text-xs font-bold text-blue-400 bg-blue-900/10 hover:bg-blue-900/20 border border-blue-500/30 transition-all uppercase tracking-wider font-mono">
                                New Scan
                            </Link>
                            <button onClick={() => window.print()} className="px-6 py-3 text-xs font-bold text-black bg-blue-600 hover:bg-blue-500 transition-all uppercase tracking-wider shadow-[0_0_15px_rgba(59,130,246,0.5)] font-mono">
                                Export Report
                            </button>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

                        {/* LEFT COLUMN: Trust Score & Summary */}
                        <div className="lg:col-span-1 space-y-6">

                            {/* Trust Score Card */}
                            <div className="bg-black/80 backdrop-blur-md p-8 border border-blue-900/30 relative overflow-hidden shadow-[0_0_30px_rgba(0,0,0,0.5)] relative">
                                <h3 className="text-blue-500 font-bold uppercase tracking-widest text-xs mb-8 text-center border-b border-blue-900/30 pb-4 font-mono">Security Trust Score</h3>

                                <div className="relative w-56 h-56 mx-auto mb-8 flex items-center justify-center">
                                    {/* SVG Gauge */}
                                    <svg className="w-full h-full transform -rotate-90" viewBox="0 0 200 200">
                                        <circle cx="100" cy="100" r={radius} stroke="#111827" strokeWidth="8" fill="transparent" className="gauge-bg" />
                                        <motion.circle
                                            initial={{ strokeDashoffset: circumference }}
                                            animate={{ strokeDashoffset: offset }}
                                            transition={{ duration: 1.5, ease: "easeOut" }}
                                            cx="100" cy="100" r={radius}
                                            stroke="currentColor" strokeWidth="8" fill="transparent"
                                            strokeDasharray={circumference}
                                            strokeDashoffset={offset}
                                            strokeLinecap="round"
                                            className={gaugeColor}
                                            style={{ filter: "drop-shadow(0 0 10px currentColor)" }}
                                        />
                                    </svg>
                                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                                        <span className="text-7xl font-bold text-white tracking-tighter font-mono">{scan.final_score}</span>
                                        <span className="text-xs text-gray-500 font-mono uppercase">/ 100</span>
                                    </div>
                                </div>

                                {/* Stats */}
                                <div className="flex justify-between border-t border-blue-900/30 pt-6">
                                    <div className="text-center w-1/2 border-r border-blue-900/30">
                                        <span className="block text-2xl font-bold text-green-500 font-mono">{positiveSignals}</span>
                                        <span className="text-[10px] text-gray-500 uppercase tracking-wider font-mono">Passed</span>
                                    </div>
                                    <div className="text-center w-1/2">
                                        <span className="block text-2xl font-bold text-red-500 font-mono">{negativeSignals}</span>
                                        <span className="text-[10px] text-gray-500 uppercase tracking-wider font-mono">Issues</span>
                                    </div>
                                </div>
                            </div>

                            {/* Info Box */}
                            <div className="bg-blue-900/5 border border-blue-500/20 p-4 text-[10px] text-blue-300 font-mono leading-relaxed text-justify relative">
                                <div className="absolute top-0 left-0 w-2 h-2 border-t border-l border-blue-500"></div>
                                <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r border-blue-500"></div>
                                This report is generated based on real-time heuristics and third-party threat intelligence.
                                Scores are calculated using a weighted algorithm prioritizing SSL validity, domain reputation, and historical behavior.
                            </div>

                        </div>

                        {/* RIGHT COLUMN: Details & Tabs */}
                        <div className="lg:col-span-2 space-y-6">

                            {/* Tab Switcher - Centered Top */}
                            <div className="flex justify-start tabs-container">
                                <div className="flex gap-2">
                                    {['overview', 'security', 'domain'].map((tab) => (
                                        <button
                                            key={tab}
                                            onClick={() => setActiveTab(tab)}
                                            className={`px-6 py-2 text-xs font-bold uppercase tracking-wider transition-all border font-mono ${activeTab === tab
                                                ? 'bg-blue-600 text-black border-blue-600 shadow-[0_0_15px_rgba(37,99,235,0.3)]'
                                                : 'text-gray-500 hover:text-white border-white/10 hover:border-white/30 bg-white/5'
                                                }`}
                                        >
                                            {tab}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Content Area */}
                            <div className="min-h-[400px]">
                                {activeTab === 'overview' && (
                                    <div className="space-y-3">
                                        {scan.signals.length === 0 ? (
                                            <div className="p-12 text-center text-gray-500 border border-dashed border-white/10 font-mono text-sm">NO SIGNALS DETECTED</div>
                                        ) : (
                                            scan.signals.sort((a, b) => b.weight - a.weight).map((signal, idx) => (
                                                <motion.div
                                                    key={idx}
                                                    initial={{ opacity: 0, x: -10 }}
                                                    animate={{ opacity: 1, x: 0 }}
                                                    transition={{ delay: idx * 0.05 }}
                                                    className={`group hover:bg-blue-900/20 transition-all p-4 border-l-2 backdrop-blur-md ${signal.impact === 'critical' ? 'border-l-red-500 bg-black/80 border border-red-500/30' :
                                                        signal.impact === 'warning' ? 'border-l-yellow-500 bg-black/80 border border-yellow-500/30' :
                                                            signal.impact === 'positive' ? 'border-l-green-500 bg-black/80 border border-green-500/30' :
                                                                'border-l-gray-600 bg-black/80 border border-white/10'
                                                        }`}
                                                >
                                                    <div className="flex justify-between items-start">
                                                        <div>
                                                            <div className="flex items-center gap-3 mb-2">
                                                                <h4 className="text-white font-bold text-xs tracking-wide uppercase font-mono">{signal.type.replace(/_/g, ' ')}</h4>
                                                                <span className={`text-[9px] font-bold px-1.5 py-0.5 border font-mono uppercase ${signal.impact === 'critical' ? 'text-red-500 border-red-500/30' :
                                                                    signal.impact === 'positive' ? 'text-green-500 border-green-500/30' :
                                                                        'text-gray-500 border-gray-600/30'
                                                                    }`}>{signal.impact}</span>
                                                            </div>
                                                            <p className="text-gray-400 text-xs leading-relaxed font-mono">{signal.description}</p>
                                                        </div>
                                                    </div>
                                                </motion.div>
                                            ))
                                        )}
                                    </div>
                                )}

                                {activeTab === 'security' && (
                                    <div className="bg-black/80 backdrop-blur-md border border-blue-900/30 p-6 relative">
                                        <div className="absolute top-0 right-0 w-4 h-4 border-t border-r border-blue-500/50"></div>
                                        <div className="absolute bottom-0 left-0 w-4 h-4 border-b border-l border-blue-500/50"></div>

                                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6 border-b border-blue-900/30 pb-4">
                                            <h3 className="text-blue-400 font-bold flex items-center gap-3 text-xs uppercase tracking-wider font-mono shrink-0">
                                                <span>🛡️</span> Threat Intelligence
                                            </h3>
                                            {/* Inner Tab Switcher */}
                                            <div className="flex gap-1 overflow-x-auto max-w-full pb-2 md:pb-0 -mx-4 px-4 md:mx-0 md:px-0 no-scrollbar">
                                                {['detection', 'details', 'relations', 'community', 'google sb'].map((tab) => (
                                                    <button
                                                        key={tab}
                                                        onClick={() => setVtTab(tab)}
                                                        className={`px-3 py-1 text-[10px] uppercase font-bold tracking-wider transition-all border font-mono whitespace-nowrap shrink-0 ${vtTab === tab
                                                            ? 'bg-blue-600 text-black border-blue-600'
                                                            : 'text-gray-500 hover:text-white border-transparent hover:border-white/10'
                                                            }`}
                                                    >
                                                        {tab}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>

                                        {vtTab === 'detection' && (
                                            <>
                                                {Object.keys(vendors).length > 0 ? (
                                                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                                                        {Object.entries(vendors).map(([vendor, result]) => (
                                                            <div key={vendor} className="flex items-center justify-between bg-black p-2 px-3 border border-white/10 hover:border-blue-500/50 transition-colors">
                                                                <span className="text-gray-400 truncate max-w-[80px] font-mono text-[10px] uppercase">{vendor}</span>
                                                                <span className={`font-bold text-[10px] font-mono uppercase ${result.category === 'malicious' ? 'text-red-500 animate-pulse' :
                                                                    result.category === 'suspicious' ? 'text-yellow-500' : 'text-green-500'
                                                                    }`}>
                                                                    {result.result === 'clean' ? 'CLEAN' : result.result}
                                                                </span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                ) : (
                                                    <div className="text-center py-16 text-gray-500 border border-dashed border-white/10">
                                                        <p className="mb-2 text-3xl opacity-50">📡</p>
                                                        <p className="uppercase tracking-widest text-xs font-mono">No vendor data available</p>
                                                        <p className="text-[10px] mt-2 text-gray-600 font-mono">Ensure scanning is complete.</p>
                                                    </div>
                                                )}
                                            </>
                                        )}

                                        {vtTab === 'details' && (
                                            <div className="space-y-8">

                                                {/* DNS Records */}
                                                <div>
                                                    <h4 className="text-white text-[10px] uppercase font-bold tracking-widest mb-3 border-l-2 border-blue-500 pl-3 flex items-center gap-2">
                                                        Last DNS Records <span className="text-gray-600 text-[9px]">({dnsRecords.length})</span>
                                                    </h4>
                                                    {dnsRecords.length > 0 ? (
                                                        <div className="overflow-x-auto">
                                                            <table className="w-full text-left border-collapse font-mono text-[10px]">
                                                                <thead>
                                                                    <tr className="border-b border-white/10 text-gray-500">
                                                                        <th className="py-2 px-2">Type</th>
                                                                        <th className="py-2 px-2">TTL</th>
                                                                        <th className="py-2 px-2">Value</th>
                                                                    </tr>
                                                                </thead>
                                                                <tbody>
                                                                    {dnsRecords.slice(0, 5).map((record, i) => (
                                                                        <tr key={i} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                                                                            <td className="py-2 px-2 text-blue-400 font-bold">{record.type}</td>
                                                                            <td className="py-2 px-2 text-gray-400">{record.ttl}</td>
                                                                            <td className="py-2 px-2 text-white break-all max-w-[200px]">{record.value}</td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                            {dnsRecords.length > 5 && <p className="text-[9px] text-gray-600 mt-2 italic">Showing top 5 records...</p>}
                                                        </div>
                                                    ) : <p className="text-gray-600 text-[10px] italic bg-white/5 p-3">No DNS records available.</p>}
                                                </div>

                                                {/* HTTPS Certificate */}
                                                <div>
                                                    <h4 className="text-white text-[10px] uppercase font-bold tracking-widest mb-3 border-l-2 border-blue-500 pl-3">Last HTTPS Certificate</h4>
                                                    {sslCert ? (
                                                        <div className="bg-[#050505] p-4 border border-white/5 font-mono text-[10px] space-y-3">

                                                            {/* JARM */}
                                                            {jarm && (
                                                                <div className="mb-4 pb-4 border-b border-white/5">
                                                                    <span className="block text-gray-500 mb-1 font-bold">JARM Fingerprint</span>
                                                                    <span className="text-blue-500/80 break-all">{jarm}</span>
                                                                </div>
                                                            )}

                                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                                <div>
                                                                    <span className="block text-gray-500 mb-1 font-bold">Subject</span>
                                                                    <div className="text-gray-300 pl-2 border-l border-white/10">
                                                                        <div className="grid grid-cols-[30px_1fr] gap-1">
                                                                            <span className="text-gray-600">CN:</span> <span className="text-white">{sslCert.subject?.CN}</span>
                                                                            <span className="text-gray-600">O:</span> <span className="text-white">{sslCert.subject?.O}</span>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                                <div>
                                                                    <span className="block text-gray-500 mb-1 font-bold">Issuer</span>
                                                                    <div className="text-gray-300 pl-2 border-l border-white/10">
                                                                        <div className="grid grid-cols-[30px_1fr] gap-1">
                                                                            <span className="text-gray-600">CN:</span> <span className="text-white">{sslCert.issuer?.CN}</span>
                                                                            <span className="text-gray-600">O:</span> <span className="text-white">{sslCert.issuer?.O}</span>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            </div>

                                                            <div className="grid grid-cols-2 gap-4 pt-3 border-t border-white/5">
                                                                <div>
                                                                    <span className="text-gray-500 block">Valid From</span>
                                                                    <span className="text-green-500">{sslCert.validity?.not_before}</span>
                                                                </div>
                                                                <div>
                                                                    <span className="text-gray-500 block">Valid To</span>
                                                                    <span className="text-green-500">{sslCert.validity?.not_after}</span>
                                                                </div>
                                                            </div>

                                                            <div className="pt-3 border-t border-white/5">
                                                                <span className="text-gray-500 block mb-1">Thumbprint (SHA-256)</span>
                                                                <span className="text-gray-400 break-all text-[9px]">{sslCert.thumbprint_sha256}</span>
                                                            </div>
                                                        </div>
                                                    ) : <p className="text-gray-600 text-[10px] italic bg-white/5 p-3">No certificate data available.</p>}
                                                </div>

                                            </div>
                                        )}

                                        {vtTab === 'relations' && (
                                            <div className="space-y-6">
                                                <div>
                                                    <h4 className="text-white text-[10px] uppercase font-bold tracking-widest mb-3 border-l-2 border-blue-500 pl-3">Popularity Ranks</h4>
                                                    <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                                        {Object.entries(popularity).map(([source, rank]) => (
                                                            <div key={source} className="bg-white/5 p-2 px-3 border border-white/5 flex justify-between items-center">
                                                                <span className="text-gray-500 text-[9px] uppercase">{source}</span>
                                                                <span className="text-blue-400 font-mono font-bold text-[10px]">#{rank.rank}</span>
                                                            </div>
                                                        ))}
                                                        {Object.keys(popularity).length === 0 && <span className="text-gray-600 text-[10px] italic p-2">No popularity data.</span>}
                                                    </div>
                                                </div>

                                                <div className="bg-[#050505] p-6 border border-white/10 flex flex-col items-center justify-center text-center space-y-4">
                                                    <div className="p-4 rounded-full bg-blue-900/10 text-blue-500 mb-2">
                                                        <svg className="w-8 h-8 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                                                    </div>
                                                    <h3 className="text-gray-400 font-bold uppercase tracking-widest text-xs">Relations Graph</h3>
                                                    <p className="text-gray-600 text-[10px] max-w-xs mx-auto">
                                                        Deep relationship analysis (Passive DNS, Siblings) requires premium API access.
                                                        Current plan is limited to snapshot data.
                                                    </p>
                                                </div>
                                            </div>
                                        )}

                                        {vtTab === 'community' && (
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                                <div>
                                                    <h4 className="text-white text-[10px] uppercase font-bold tracking-widest mb-4 border-l-2 border-blue-500 pl-3">Crowdsourced Voting</h4>
                                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                        <div className="bg-green-900/10 border border-green-500/30 p-4 text-center">
                                                            <span className="block text-2xl font-bold text-green-500 font-mono">{votes.harmless || 0}</span>
                                                            <span className="text-[10px] text-green-400 uppercase tracking-wider">Harmless</span>
                                                        </div>
                                                        <div className="bg-red-900/10 border border-red-500/30 p-4 text-center">
                                                            <span className="block text-2xl font-bold text-red-500 font-mono">{votes.malicious || 0}</span>
                                                            <span className="text-[10px] text-red-400 uppercase tracking-wider">Malicious</span>
                                                        </div>
                                                    </div>
                                                </div>

                                                <div>
                                                    <h4 className="text-white text-[10px] uppercase font-bold tracking-widest mb-4 border-l-2 border-blue-500 pl-3">Submission History</h4>
                                                    <div className="bg-white/5 p-4 border border-white/5 space-y-3 font-mono text-[10px]">
                                                        <div>
                                                            <span className="block text-gray-500 mb-1">Last Submission</span>
                                                            <span className="text-white">
                                                                {submission.date
                                                                    ? new Date(submission.date * 1000).toUTCString()
                                                                    : 'Unknown'}
                                                            </span>
                                                        </div>
                                                        <div className="pt-3 border-t border-white/5">
                                                            <span className="block text-gray-500 mb-1">Analysis Stats</span>
                                                            <div className="flex gap-4">
                                                                <span className="text-red-500">Malicious: {vtData?.stats?.malicious || 0}</span>
                                                                <span className="text-yellow-500">Suspicious: {vtData?.stats?.suspicious || 0}</span>
                                                                <span className="text-green-500">Harmless: {vtData?.stats?.harmless || 0}</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        )}

                                        {vtTab === 'google sb' && (
                                            <div>
                                                <div className="flex items-center gap-3 mb-6">
                                                    <div className="p-2 bg-white rounded-full">
                                                        {/* Google G Icon SVG */}
                                                        <svg className="w-6 h-6" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                                            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                                                            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                                                            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
                                                            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <h4 className="text-white font-bold uppercase tracking-wider text-xs">Google Safe Browsing</h4>
                                                        <p className="text-gray-500 text-[10px]">Transparency Report & Threat Verification</p>
                                                    </div>
                                                </div>

                                                <div className="bg-[#050505] p-6 border border-white/10">
                                                    <h5 className="text-gray-400 text-[10px] uppercase font-bold mb-4 tracking-widest">Verified Threat Intelligence Checks</h5>
                                                    <div className="space-y-3">
                                                        {gsbThreats.length > 0 ? (
                                                            gsbThreats.map((threat, i) => (
                                                                <div key={i} className="flex items-center justify-between border-b border-white/5 pb-2 last:border-0 last:pb-0">
                                                                    <span className="text-gray-300 text-[10px] font-mono tracking-wide">{threat.replace(/_/g, ' ')}</span>
                                                                    <div className="flex items-center gap-2">
                                                                        <span className="text-green-500 text-[10px] font-bold uppercase tracking-wider">Verified Safe</span>
                                                                        <svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path></svg>
                                                                    </div>
                                                                </div>
                                                            ))
                                                        ) : (
                                                            <div className="text-center text-gray-500 py-4 italic text-[10px] border border-dashed border-white/10">
                                                                <p className="mb-2">⚠️</p>
                                                                <p>No explicit threat checks returned.</p>
                                                                <p className="text-[9px] mt-1">This usually means the API key is missing or the request failed.</p>
                                                            </div>
                                                        )}
                                                    </div>
                                                    <div className="mt-6 p-3 bg-blue-900/10 border border-blue-500/20 text-[9px] text-blue-400 text-center font-mono">
                                                        Authenticated via Google Safe Browsing API v4
                                                    </div>
                                                </div>
                                            </div>
                                        )}

                                    </div>
                                )}

                                {activeTab === 'domain' && (
                                    <div className="bg-black/80 backdrop-blur-md border border-blue-900/30 p-6 space-y-6 relative">
                                        <div className="absolute top-0 right-0 w-4 h-4 border-t border-r border-blue-500/50"></div>
                                        <div className="absolute bottom-0 left-0 w-4 h-4 border-b border-l border-blue-500/50"></div>

                                        <div>
                                            <h3 className="text-blue-400 font-bold mb-6 flex items-center gap-3 text-xs uppercase tracking-wider border-b border-blue-900/30 pb-4 font-mono">
                                                <span>🌐</span> Domain Reconnaissance
                                            </h3>

                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                <div className="bg-white/5 p-4 border-l-2 border-l-blue-500 border border-white/5">
                                                    <span className="text-gray-500 text-[10px] uppercase tracking-widest font-bold block mb-1 font-mono">Creation Date</span>
                                                    <span className="text-white text-sm font-mono">
                                                        {domainData.creation_date
                                                            ? new Date(domainData.creation_date * 1000).toLocaleDateString(undefined, { dateStyle: 'medium' })
                                                            : 'UNKNOWN / HIDDEN'
                                                        }
                                                    </span>
                                                </div>

                                                <div className="bg-white/5 p-4 border-l-2 border-l-blue-500 border border-white/5">
                                                    <span className="text-gray-500 text-[10px] uppercase tracking-widest font-bold block mb-1 font-mono">Registrar</span>
                                                    <span className="text-white text-sm font-mono truncate block" title={domainData.registrar}>
                                                        {domainData.registrar || 'UNKNOWN'}
                                                    </span>
                                                </div>

                                                <div className="bg-white/5 p-4 border border-white/5 md:col-span-2">
                                                    <span className="text-gray-500 text-[10px] uppercase tracking-widest font-bold block mb-3 font-mono">Reputation Tags</span>
                                                    <div className="flex flex-wrap gap-2">
                                                        {Object.keys(domainData.categories || {}).length > 0 ?
                                                            Object.keys(domainData.categories).map(cat => (
                                                                <span key={cat} className="px-2 py-1 bg-blue-900/20 text-blue-400 text-[10px] border border-blue-500/30 uppercase tracking-wide font-mono">
                                                                    {domainData.categories[cat]}
                                                                </span>
                                                            ))
                                                            : <span className="text-gray-600 text-xs italic font-mono">No specific categories tags found.</span>}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Disclaimer */}
                    <div className="mt-12 pt-8 border-t border-white/5 text-center no-print">
                        <p className="text-[10px] text-gray-600 max-w-2xl mx-auto uppercase tracking-wider font-mono">
                            <strong>Security Disclaimer:</strong> Analysis provided for informational purposes only.
                            Automated heuristics may produce false positives. Always verify critical indicators manually.
                        </p>
                    </div>
                </motion.div>
            </main>
        </div>
    );
}
