import React from 'react';
import { useForm } from '@inertiajs/react';
import { motion } from 'framer-motion';
import MatrixRain from '../Components/MatrixRain';

export default function Welcome() {
    const { data, setData, post, processing, errors } = useForm({
        url: '',
    });

    const handleSubmit = (e) => {
        e.preventDefault();
        post('/scan');
    };

    return (
        <div className="min-h-screen text-white font-sans selection:bg-blue-500/30 flex flex-col relative overflow-x-hidden">
            <MatrixRain />

            <nav className="relative z-50 p-6 w-full border-b border-white/5 bg-[#0a0a0a]/50 backdrop-blur-md">
                <div className="max-w-7xl mx-auto flex justify-between items-center">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-blue-900/30 border border-blue-500/50 flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)]">
                            <span className="text-xl">🛡️</span>
                        </div>
                        <span className="text-xl font-bold tracking-tight text-white uppercase font-mono">
                            amangaknih.id
                        </span>
                    </div>
                    <a href="https://github.com/itzcaesar/aman-gak-nih" className="text-sm font-bold text-gray-400 hover:text-white transition-colors border border-white/10 px-4 py-2 hover:bg-white/5 uppercase tracking-wider font-mono">
                        GitHub
                    </a>
                </div>
            </nav>

            <main className="relative z-10 flex-grow flex flex-col items-center justify-center px-4 py-20">

                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8 }}
                    className="max-w-4xl w-full text-center space-y-10"
                >
                    <div className="inline-flex items-center gap-3 px-4 py-1.5 bg-blue-900/10 border border-blue-500/30 backdrop-blur-md">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full bg-blue-400 opacity-75"></span>
                            <span className="relative inline-flex h-2 w-2 bg-blue-500"></span>
                        </span>
                        <span className="text-xs font-mono text-blue-400 tracking-widest uppercase">SYSTEM ONLINE // READY TO SCAN</span>
                    </div>

                    <h1 className="text-5xl md:text-7xl font-bold tracking-tighter text-white leading-tight">
                        VERIFY DIGITAL <span className="text-transparent bg-clip-text bg-gradient-to-b from-blue-400 to-blue-600">TRUST</span>
                    </h1>

                    <p className="text-lg text-gray-400 font-mono text-sm max-w-xl mx-auto leading-relaxed border-l-2 border-blue-500/30 pl-4 text-left md:text-center md:border-l-0 md:pl-0">
                        ANALYZE SUSPICIOUS LINKS WITH ADVANCED THREAT INTELLIGENCE.
                        DETECT PHISHING, MALWARE, AND FRAUD IN REAL-TIME.
                    </p>

                    <div className="mt-12 max-w-xl mx-auto relative group z-20">
                        <form onSubmit={handleSubmit} className="relative flex items-center bg-[#0a0a0a] border border-blue-900/50 focus-within:border-blue-500 transition-all shadow-[0_0_50px_rgba(0,0,0,0.5)]">
                            <div className="absolute left-0 top-0 bottom-0 w-1 bg-blue-600"></div>

                            <div className="pl-6 text-blue-500">
                                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                            </div>

                            <input
                                type="text"
                                value={data.url}
                                onChange={e => setData('url', e.target.value)}
                                className="w-full bg-transparent border-none text-white text-lg placeholder-gray-600 px-4 py-6 focus:ring-0 font-mono outline-none"
                                placeholder="ENTER TARGET URL..."
                                required
                                autoFocus
                                spellCheck="false"
                            />

                            <button
                                type="submit"
                                disabled={processing}
                                className="mr-2 px-8 py-3 bg-blue-600 hover:bg-blue-500 text-black font-bold uppercase tracking-wider transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                            >
                                {processing ? (
                                    <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                                ) : 'SCAN'}
                            </button>
                        </form>
                    </div>

                    {errors.url && (
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-4 text-red-500 text-xs font-mono bg-red-900/10 inline-block px-4 py-2 border border-red-500/30 uppercase">
                            ⚠️ {errors.url}
                        </motion.div>
                    )}

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-20 pt-10 border-t border-white/5">
                        <div className="flex flex-col items-center p-6 border border-white/5 bg-black/60 backdrop-blur-md hover:border-blue-500/30 transition-colors group cursor-default">
                            <span className="text-2xl mb-4 text-gray-500 group-hover:text-blue-400 transition-colors">🔒</span>
                            <span className="text-[10px] text-gray-500 uppercase tracking-widest font-bold font-mono">SSL Analysis</span>
                            <span className="text-sm font-bold text-white mt-2 group-hover:text-blue-400">GRADE A+</span>
                        </div>
                        <div className="flex flex-col items-center p-6 border border-white/5 bg-black/60 backdrop-blur-md hover:border-blue-500/30 transition-colors group cursor-default">
                            <span className="text-2xl mb-4 text-gray-500 group-hover:text-blue-400 transition-colors">📅</span>
                            <span className="text-[10px] text-gray-500 uppercase tracking-widest font-bold font-mono">Domain Age</span>
                            <span className="text-sm font-bold text-white mt-2 group-hover:text-blue-400">WHOIS CHECK</span>
                        </div>
                        <div className="flex flex-col items-center p-6 border border-white/5 bg-black/60 backdrop-blur-md hover:border-blue-500/30 transition-colors group cursor-default">
                            <span className="text-2xl mb-4 text-gray-500 group-hover:text-blue-400 transition-colors">⚡</span>
                            <span className="text-[10px] text-gray-500 uppercase tracking-widest font-bold font-mono">Fast Scan</span>
                            <span className="text-sm font-bold text-white mt-2 group-hover:text-blue-400">&lt; 5 SECONDS</span>
                        </div>
                        <div className="flex flex-col items-center p-6 border border-white/5 bg-black/60 backdrop-blur-md hover:border-blue-500/30 transition-colors group cursor-default">
                            <span className="text-2xl mb-4 text-gray-500 group-hover:text-blue-400 transition-colors">🤖</span>
                            <span className="text-[10px] text-gray-500 uppercase tracking-widest font-bold font-mono">AI Engine</span>
                            <span className="text-sm font-bold text-white mt-2 group-hover:text-blue-400">ACTIVE</span>
                        </div>
                    </div>

                </motion.div>
            </main>

            <footer className="relative z-10 border-t border-white/5 bg-[#0a0a0a] py-8">
                <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center text-xs text-gray-600 font-mono uppercase tracking-wider">
                    <p>© {new Date().getFullYear()} AMANGAKNIH.ID // OPEN SOURCE SECURITY</p>
                    <div className="flex gap-6 mt-4 md:mt-0">
                        <span>POWERED BY VIRUSTOTAL</span>
                        <span>GOOGLE SAFE BROWSING</span>
                    </div>
                </div>
            </footer>
        </div>
    );
}
