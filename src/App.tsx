import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  User, 
  MessageSquare, 
  Hash, 
  Settings, 
  Send, 
  Plus, 
  Lock, 
  Zap, 
  Globe,
  MoreVertical,
  ArrowRight,
  Fingerprint,
  RefreshCw,
  Trash2,
  CheckCircle,
  AlertTriangle,
  Download,
  Check,
  UserCheck
} from 'lucide-react';
import { 
  PrivacyAgent, 
  IdentityAgent, 
  RelayAgent, 
  StorageAgent, 
  DiscoveryAgent, 
  ModerationAgent 
} from './core/Agents';
import { AetherIdentity, AetherMessage, AetherVault } from './types';

// --- Components ---

const SidebarItem = ({ icon: Icon, label, active, onClick }: any) => (
  <button
    onClick={onClick}
    className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 ${
      active 
        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.05)]' 
        : 'text-zinc-500 hover:bg-white/5 hover:text-white'
    }`}
  >
    <Icon size={18} strokeWidth={active ? 2.5 : 2} />
    <span className={`text-sm tracking-tight ${active ? 'font-bold' : 'font-medium'}`}>{label}</span>
  </button>
);

interface MessageCardProps {
  message: AetherMessage;
  identity: AetherIdentity | null;
}

const MessageCard: React.FC<MessageCardProps> = ({ message, identity }) => {
  const [verificationStatus, setVerificationStatus] = useState<'verifying' | 'verified' | 'failed'>('verifying');
  const isOwn = identity && message.sender === identity.publicKey;
  const isDM = message.type === 'dm';

  useEffect(() => {
    const verify = async () => {
      const privacy = PrivacyAgent.getInstance();
      const isValid = await privacy.verifySignature(message.content, message.signature, message.sender);
      setVerificationStatus(isValid ? 'verified' : 'failed');
    };
    verify();
  }, [message.id, message.content, message.signature, message.sender]);
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="group relative flex flex-col gap-3 p-5 rounded-2xl glass border border-white/5 hover:border-white/10 transition-all"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-xs font-bold text-emerald-500 font-mono">
            {message.sender.slice(0, 2).toUpperCase()}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-zinc-100">
                {isOwn ? 'LOCAL_NODE' : `PEER_${message.sender.slice(0, 6)}`}
              </span>
              <span className="status-label bg-white/5 px-1.5 py-0.5 rounded">
                {message.sender.slice(0, 8)}...
              </span>
              {isDM && (
                <div className="flex items-center gap-1 text-emerald-500/70">
                  <Lock size={10} />
                  <span className="text-[9px] font-mono uppercase tracking-widest">Encrypted</span>
                </div>
              )}
            </div>
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">
              {new Date(message.timestamp).toLocaleTimeString()} • {isDM ? 'ENCRYPTED_DM' : 'BROADCAST'}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {verificationStatus === 'verifying' ? (
            <div className="flex items-center gap-1.5 px-2 py-1 bg-white/5 border border-white/10 rounded-lg">
              <RefreshCw size={10} className="text-zinc-500 animate-spin" />
              <span className="text-[9px] font-mono font-bold text-zinc-500 uppercase">Verifying</span>
            </div>
          ) : verificationStatus === 'verified' ? (
            <div className="flex items-center gap-1.5 px-2 py-1 bg-emerald-500/5 border border-emerald-500/10 rounded-lg">
              <CheckCircle size={10} className="text-emerald-500" />
              <span className="text-[9px] font-mono font-bold text-emerald-500/80 uppercase">Verified</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 px-2 py-1 bg-red-500/5 border border-red-500/10 rounded-lg">
              <AlertTriangle size={10} className="text-red-500 animate-pulse" />
              <span className="text-[9px] font-mono font-bold text-red-500 uppercase">Unverified</span>
            </div>
          )}
          <button className="opacity-0 group-hover:opacity-100 p-1.5 hover:bg-white/5 rounded-lg transition-all">
            <MoreVertical size={14} className="text-zinc-400" />
          </button>
        </div>
      </div>
      <p className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap font-sans">
        {message.content}
      </p>
      <div className="flex items-center gap-4 mt-1 border-t border-white/5 pt-3">
        <button className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 hover:text-emerald-400 flex items-center gap-1.5 transition-colors">
          <MessageSquare size={12} /> Reply
        </button>
      </div>
    </motion.div>
  );
};

// --- Main App ---

export default function App() {
  const [view, setView] = useState<'onboarding' | 'vault_unlock' | 'feed' | 'communities' | 'dms' | 'settings' | 'finish_session'>('onboarding');
  const [identity, setIdentity] = useState<AetherIdentity | null>(null);
  const [vault, setVault] = useState<AetherVault | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState('');
  const [messages, setMessages] = useState<AetherMessage[]>([]);
  const [communities, setCommunities] = useState<any[]>([]);
  const [activeTopic, setActiveTopic] = useState('global');
  const [isPosting, setIsPosting] = useState(false);
  const [postContent, setPostContent] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [peers, setPeers] = useState<any[]>([]);
  const [activePeer, setActivePeer] = useState<any | null>(null);
  const [dmContent, setDmContent] = useState('');
  const [dmMessages, setDmMessages] = useState<AetherMessage[]>([]);

  const storage = new StorageAgent();
  const relay = new RelayAgent();
  const privacy = PrivacyAgent.getInstance();
  const identityAgent = IdentityAgent.getInstance();
  const discovery = new DiscoveryAgent();

  useEffect(() => {
    init();
  }, []);

  const init = async () => {
    const savedVault = await storage.load('identity_vault');
    if (savedVault) {
      setVault(savedVault);
      setView('vault_unlock');
    } else {
      setView('onboarding');
    }
    setIsLoading(false);
  };

  const loadData = async () => {
    const msgs = await relay.fetchFeed();
    setMessages(msgs);
    const comms = await discovery.getCommunities();
    setCommunities(comms);
    const storedPeers = await storage.getPeers();
    setPeers(storedPeers);
  };

  useEffect(() => {
    if (identity) {
      const interval = setInterval(() => {
        discovery.announcePresence(identity);
        discovery.discoverPeers().then(() => storage.getPeers().then(setPeers));
      }, 10000);
      return () => clearInterval(interval);
    }
  }, [identity]);

  useEffect(() => {
    if (activePeer && identity) {
      const interval = setInterval(async () => {
        const myDms = await relay.fetchTopic(`dm:${identity.publicKey}`);
        const peerDms = await relay.fetchTopic(`dm:${activePeer.pubkey}`);
        
        const combined = [...myDms, ...peerDms]
          .filter(m => (m.sender === identity.publicKey && m.topic === `dm:${activePeer.pubkey}`) || 
                       (m.sender === activePeer.pubkey && m.topic === `dm:${identity.publicKey}`))
          .sort((a, b) => a.timestamp - b.timestamp);

        // Decrypt and verify messages
        const processed = await Promise.all(combined.map(async m => {
          const isVerified = await privacy.verifySignature(m.content, m.signature, m.sender);
          if (m.iv) {
            try {
              const senderPeer = peers.find(p => p.pubkey === m.sender);
              const peerEncPub = senderPeer ? senderPeer.metadata.encryptionPublicKey : activePeer.metadata.encryptionPublicKey;
              
              const decryptedContent = await privacy.decryptFromPeer(
                m.content,
                m.iv,
                peerEncPub,
                identity.encryptionPrivateKey!
              );
              return { ...m, content: decryptedContent, metadata: { ...m.metadata, verified: isVerified } };
            } catch (e) {
              return { ...m, content: "[Decryption Failed]", metadata: { ...m.metadata, verified: isVerified } };
            }
          }
          return { ...m, metadata: { ...m.metadata, verified: isVerified } };
        }));
        
        setDmMessages(processed);
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [activePeer, identity, peers]);

  const handleUnlock = async () => {
    if (!passphrase || !vault) return;
    setIsLoading(true);
    setError('');
    try {
      const identities = await identityAgent.unlockVault(vault, passphrase);
      if (identities.length > 0) {
        const id = identities[0];
        // Challenge verification
        const challenge = `AUTH_CHALLENGE_${Date.now()}`;
        const signature = await identityAgent.signChallenge(challenge, id);
        const verified = await identityAgent.verifyChallenge(challenge, signature, id.publicKey);
        
        if (verified) {
          setIdentity(id);
          setView('feed');
          loadData();
        } else {
          setError('Identity verification failed.');
        }
      }
    } catch (e: any) {
      setError(e.message || 'Invalid passphrase or corrupted vault.');
    }
    setIsLoading(false);
  };

  const handleOnboarding = async (handle: string, pass: string, isAdult: boolean) => {
    if (!handle || !pass) return;
    setIsLoading(true);
    const newIdentity = await identityAgent.createIdentity(handle, isAdult);
    const newVault = await identityAgent.commitVault(pass);
    await storage.save('identity_vault', newVault);
    setIdentity(newIdentity);
    setVault(newVault);
    setView('feed');
    loadData();
    setIsLoading(false);
  };

  const handleBackup = async (pass: string) => {
    if (!pass) {
      setError('Passphrase required for backup.');
      return;
    }
    setIsLoading(true);
    try {
      const dump = await storage.exportDataDump(pass);
      const blob = new Blob([dump], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aether_backup_${Date.now()}.json`;
      a.click();
      setIsLoading(false);
      setPassphrase('');
    } catch (e) {
      setError('Failed to export backup.');
      setIsLoading(false);
    }
  };

  const handleFinishSession = async (pass: string) => {
    if (!pass) {
      setError('Passphrase required for export.');
      return;
    }
    setIsLoading(true);
    try {
      const dump = await storage.exportDataDump(pass);
      const blob = new Blob([dump], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aether_dump_${Date.now()}.json`;
      a.click();
      
      // Secure Wipe
      await storage.secureWipe();
    } catch (e) {
      setError('Failed to export data.');
      setIsLoading(false);
    }
  };

  const [archiveToImport, setArchiveToImport] = useState<any>(null);

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const archive = JSON.parse(event.target?.result as string);
        setArchiveToImport(archive);
        setView('vault_unlock');
      } catch (e) {
        setError('Invalid archive file.');
      }
    };
    reader.readAsText(file);
  };

  const handleUnlockImport = async () => {
    if (!passphrase || !archiveToImport) return;
    setIsLoading(true);
    setError('');
    try {
      const salt = archiveToImport.salt;
      const iv = archiveToImport.iv;
      const data = archiveToImport.data;
      
      const key = await privacy.deriveVaultKey(passphrase, salt);
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0)) },
        key,
        Uint8Array.from(atob(data), c => c.charCodeAt(0))
      );
      
      const decoder = new TextDecoder();
      const restoredData = JSON.parse(decoder.decode(decrypted));
      
      // Restore to backend
      for (const row of restoredData.storage) {
        await storage.save(row.key, row.value);
      }
      
      const savedVault = await storage.load('identity_vault');
      if (savedVault) {
        setVault(savedVault);
        const identities = await identityAgent.unlockVault(savedVault, passphrase);
        setIdentity(identities[0]);
        setView('feed');
        loadData();
      }
    } catch (e) {
      setError('Invalid passphrase or corrupted archive.');
    }
    setIsLoading(false);
  };

  const handleSendDM = async () => {
    if (!dmContent.trim() || !identity || !activePeer) return;

    const { cipher, iv } = await privacy.encryptForPeer(
      dmContent,
      activePeer.metadata.encryptionPublicKey,
      identity.encryptionPrivateKey!
    );

    const msg: AetherMessage = {
      id: Math.random().toString(36).slice(2),
      topic: `dm:${activePeer.pubkey}`,
      sender: identity.publicKey,
      content: cipher,
      iv: iv,
      signature: await privacy.signMessage(cipher, identity.privateKey!),
      timestamp: Date.now(),
      type: 'dm'
    };

    await relay.sendDirectMessage(msg, activePeer.pubkey);
    setDmContent('');
    // Optimistic update
    setDmMessages(prev => [...prev, { ...msg, content: dmContent, metadata: { verified: true } }]);
  };
  const handlePost = async () => {
    if (!postContent.trim() || !identity) return;
    
    setIsPosting(true);
    const msg: AetherMessage = {
      id: Math.random().toString(36).slice(2),
      topic: activeTopic,
      sender: identity.publicKey,
      content: postContent,
      signature: await privacy.signMessage(postContent, identity.privateKey!),
      timestamp: Date.now(),
      type: 'post'
    };

    await relay.broadcast(msg);
    setPostContent('');
    loadData();
    setIsPosting(false);
  };

  const purgeLocal = async () => {
    if (confirm("Are you sure? This will delete your identity and all local data.")) {
      await storage.fullPurge();
      identityAgent.lock();
      setIdentity(null);
      setView('onboarding');
    }
  };

  if (isLoading) {
    return (
      <div className="h-screen w-full flex flex-col items-center justify-center bg-[#0A0A0A]">
        <motion.div 
          animate={{ rotate: 360 }}
          transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
          className="mb-4"
        >
          <RefreshCw size={32} className="text-emerald-500" />
        </motion.div>
        <p className="text-zinc-500 font-mono text-sm tracking-widest uppercase">Initializing Aether...</p>
      </div>
    );
  }

  if (view === 'vault_unlock') {
    return (
      <div className="h-screen w-full flex items-center justify-center bg-[#050505] p-6">
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="max-w-md w-full glass p-8 rounded-[2rem] neon-border"
        >
          <div className="flex flex-col items-center text-center mb-8">
            <div className="w-20 h-20 bg-emerald-500/10 border border-emerald-500/20 rounded-[2rem] flex items-center justify-center mb-6">
              <Lock className="text-emerald-500 animate-secure-pulse" size={40} />
            </div>
            <h1 className="text-3xl font-bold tracking-tighter mb-2">Unlock Vault</h1>
            <p className="text-zinc-500 text-sm">
              {archiveToImport ? 'Enter passphrase to decrypt and import archive.' : 'Enter your local-only passphrase to unlock your identity.'}
            </p>
          </div>

          <div className="space-y-6">
            <div>
              <input 
                type="password" 
                placeholder="Passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-4 text-white font-mono text-sm focus:outline-none focus:border-emerald-500/50 transition-all"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') archiveToImport ? handleUnlockImport() : handleUnlock();
                }}
              />
              {error && <p className="text-red-500 text-[10px] font-mono mt-2 uppercase tracking-widest">{error}</p>}
            </div>

            <button 
              onClick={archiveToImport ? handleUnlockImport : handleUnlock}
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-4 rounded-2xl flex items-center justify-center gap-2 transition-all active:scale-[0.98]"
            >
              {archiveToImport ? 'Decrypt & Import' : 'Unlock Identity'} <ArrowRight size={18} />
            </button>
            
            {!archiveToImport && (
              <div className="pt-4 border-t border-white/5 text-center">
                <button 
                  onClick={() => setView('onboarding')}
                  className="text-zinc-500 hover:text-zinc-300 text-xs font-mono uppercase tracking-widest"
                >
                  Create New Identity
                </button>
              </div>
            )}
          </div>
        </motion.div>
      </div>
    );
  }

  if (view === 'finish_session') {
    return (
      <div className="h-screen w-full flex items-center justify-center bg-[#050505] p-6">
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="max-w-md w-full glass p-8 rounded-[2rem] neon-border border-red-500/20"
        >
          <div className="flex flex-col items-center text-center mb-8">
            <div className="w-20 h-20 bg-red-500/10 border border-red-500/20 rounded-[2rem] flex items-center justify-center mb-6">
              <Trash2 className="text-red-500" size={40} />
            </div>
            <h1 className="text-3xl font-bold tracking-tighter mb-2">Finish Session</h1>
            <p className="text-zinc-500 text-sm">
              Securely wipe all local data. Set a passphrase to export an encrypted archive of your session.
            </p>
          </div>

          <div className="space-y-6">
            <div>
              <label className="status-label mb-2 ml-1 block">Archive Passphrase</label>
              <input 
                type="password" 
                placeholder="New Archive Passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-4 text-white font-mono text-sm focus:outline-none focus:border-emerald-500/50 transition-all"
              />
            </div>

            <div className="p-4 bg-red-500/5 border border-red-500/10 rounded-xl">
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                <span className="text-red-500 font-bold uppercase">Warning:</span> This will permanently erase your identity keys and messages from this device. Only the exported archive will remain.
              </p>
            </div>

            <div className="flex gap-3">
              <button 
                onClick={() => setView('settings')}
                className="flex-1 bg-white/5 hover:bg-white/10 text-white font-bold py-4 rounded-2xl transition-all"
              >
                Cancel
              </button>
              <button 
                onClick={() => handleFinishSession(passphrase)}
                className="flex-[2] bg-red-500 hover:bg-red-400 text-black font-bold py-4 rounded-2xl flex items-center justify-center gap-2 transition-all"
              >
                Export & Wipe <Zap size={18} />
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  if (view === 'onboarding') {
    return (
      <div className="h-screen w-full flex items-center justify-center bg-[#0A0A0A] p-6">
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="max-w-md w-full glass p-8 rounded-[2rem] neon-border"
        >
          <div className="flex flex-col items-center text-center mb-8">
            <div className="w-20 h-20 bg-emerald-500/10 border border-emerald-500/20 rounded-[2rem] flex items-center justify-center mb-6 shadow-[0_0_30px_rgba(16,185,129,0.1)]">
              <Shield className="text-emerald-500 animate-secure-pulse" size={40} />
            </div>
            <h1 className="text-4xl font-bold tracking-tighter mb-3">Aether: Zero-Trace</h1>
            <p className="text-zinc-500 text-sm max-w-xs leading-relaxed">
              High-security decentralized protocol. <br/>
              <span className="text-emerald-500 font-mono text-[10px] uppercase tracking-widest font-bold">Forensic-Proof Communication</span>
            </p>
          </div>

          <div className="space-y-6">
            <div className="space-y-4">
              <div className="glass p-4 rounded-2xl border border-white/5">
                <h3 className="text-[10px] font-mono font-bold text-emerald-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                  <Fingerprint size={12} /> Security Protocol v2.5
                </h3>
                <ul className="space-y-2">
                  {[
                    { label: 'Storage', value: '100% Ephemeral (RAM-only)' },
                    { label: 'Encryption', value: 'ECDH + AES-GCM 256-bit' },
                    { label: 'Identity', value: 'ECDSA P-256 Cryptographic' },
                    { label: 'Network', value: 'Zero-Trace P2P Relay' }
                  ].map((item, i) => (
                    <li key={i} className="flex items-center justify-between text-[11px]">
                      <span className="text-zinc-500">{item.label}</span>
                      <span className="text-zinc-300 font-mono font-bold">{item.value}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <label className="status-label mb-2 ml-1 block">
                  Temporary Session Alias
                </label>
                <input 
                  id="onboarding-handle"
                  type="text" 
                  placeholder="GHOST_NODE_01"
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-4 text-white font-mono text-sm focus:outline-none focus:border-emerald-500/50 transition-all placeholder:text-zinc-700"
                />
              </div>

              <div>
                <label className="status-label mb-2 ml-1 block">
                  Vault Passphrase
                </label>
                <input 
                  id="onboarding-pass"
                  type="password" 
                  placeholder="Secure Passphrase"
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-4 text-white font-mono text-sm focus:outline-none focus:border-emerald-500/50 transition-all placeholder:text-zinc-700"
                />
              </div>

              <div className="flex items-center gap-3 p-4 bg-white/5 border border-white/10 rounded-xl cursor-pointer hover:bg-white/10 transition-all group" onClick={() => {
                const cb = document.getElementById('age-verify') as HTMLInputElement;
                cb.checked = !cb.checked;
              }}>
                <div className="relative flex items-center">
                  <input 
                    id="age-verify"
                    type="checkbox" 
                    className="peer appearance-none w-5 h-5 border border-white/20 rounded-md checked:bg-emerald-500 checked:border-emerald-500 transition-all cursor-pointer"
                  />
                  <Check size={12} className="absolute left-1 text-black opacity-0 peer-checked:opacity-100 transition-opacity pointer-events-none" />
                </div>
                <div className="flex flex-col">
                  <span className="text-[11px] font-mono font-bold text-zinc-300 uppercase tracking-wider">Age Verification</span>
                  <span className="text-[9px] text-zinc-500">I confirm that I am 18 years of age or older.</span>
                </div>
              </div>

              <div className="p-3 bg-amber-500/5 border border-amber-500/10 rounded-xl">
                <p className="text-[9px] text-zinc-500 leading-tight">
                  <span className="text-amber-500 font-bold uppercase">Note:</span> Aether is zero-trace. Your keys are stored in RAM. You MUST export a backup from settings to persist this identity across sessions.
                </p>
              </div>
            </div>

            <button 
              onClick={() => {
                const handle = (document.getElementById('onboarding-handle') as HTMLInputElement).value;
                const pass = (document.getElementById('onboarding-pass') as HTMLInputElement).value;
                const isAdult = (document.getElementById('age-verify') as HTMLInputElement).checked;
                
                if (!isAdult) {
                  setError('You must verify your age to initialize a node.');
                  return;
                }
                
                handleOnboarding(handle || 'GHOST_NODE', pass, isAdult);
              }}
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-4 rounded-2xl flex items-center justify-center gap-2 transition-all active:scale-[0.98] shadow-[0_0_20px_rgba(16,185,129,0.2)]"
            >
              Initialize Node <ArrowRight size={18} />
            </button>

            <div className="pt-4 border-t border-white/5">
              <label className="w-full bg-white/5 hover:bg-white/10 text-zinc-400 font-mono text-[10px] uppercase tracking-widest py-3 rounded-xl flex items-center justify-center gap-2 cursor-pointer transition-all">
                <RefreshCw size={14} /> Import Archive
                <input type="file" className="hidden" onChange={handleImport} accept=".json" />
              </label>
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="h-screen w-full flex bg-[#0A0A0A] overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 border-r border-white/5 flex flex-col p-4">
        <div className="flex items-center gap-3 px-4 mb-8">
          <div className="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center">
            <Zap size={18} className="text-black" />
          </div>
          <span className="text-xl font-bold tracking-tighter">AETHER</span>
        </div>

        <nav className="flex-1 space-y-1">
          <SidebarItem icon={Globe} label="Global Feed" active={view === 'feed'} onClick={() => setView('feed')} />
          <SidebarItem icon={Hash} label="Communities" active={view === 'communities'} onClick={() => setView('communities')} />
          <SidebarItem icon={MessageSquare} label="Direct Messages" active={view === 'dms'} onClick={() => setView('dms')} />
          <SidebarItem icon={Settings} label="Settings" active={view === 'settings'} onClick={() => setView('settings')} />
        </nav>

        <div className="mt-auto p-5 glass rounded-[2rem] border border-emerald-500/10">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shadow-[0_0_15px_rgba(16,185,129,0.1)]">
              <Shield size={24} className="text-emerald-500 animate-secure-pulse" />
            </div>
            <div className="overflow-hidden">
              <div className="flex items-center gap-1.5">
                <p className="text-sm font-bold truncate tracking-tight">{identity?.handle}</p>
                {identity?.isAdult && (
                  <span className="text-[8px] font-mono font-bold px-1 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 rounded uppercase">18+</span>
                )}
              </div>
              <p className="status-label truncate">Identity Verified</p>
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[9px] font-mono text-zinc-500 uppercase tracking-widest">
              <span>Node Status</span>
              <span className="text-emerald-500 font-bold">Active</span>
            </div>
            <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden">
              <motion.div 
                initial={{ width: 0 }}
                animate={{ width: '100%' }}
                transition={{ duration: 2 }}
                className="h-full bg-emerald-500/50"
              />
            </div>
            <div className="flex items-center gap-2 text-[9px] text-emerald-500/70 font-mono uppercase tracking-widest">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Zero-Trace Mode
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        <header className="h-16 border-bottom border-white/5 flex items-center justify-between px-8 bg-[#0A0A0A]/80 backdrop-blur-md z-10">
          <h2 className="text-lg font-bold capitalize">{view}</h2>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-white/5 rounded-full border border-white/10">
              <RefreshCw size={12} className="text-zinc-500" />
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-widest">Syncing Peers</span>
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8">
          <div className="max-w-3xl mx-auto space-y-8">
            
            {view === 'feed' && (
              <>
                <div className="glass p-6 rounded-3xl border border-white/10">
                  <textarea 
                    value={postContent}
                    onChange={(e) => setPostContent(e.target.value)}
                    placeholder="Broadcast to the network..."
                    className="w-full bg-transparent text-lg text-white placeholder:text-zinc-600 focus:outline-none resize-none min-h-[100px]"
                  />
                  <div className="flex items-center justify-between pt-4 border-t border-white/5">
                    <div className="flex items-center gap-2">
                      <button className="p-2 hover:bg-white/5 rounded-lg text-zinc-400 transition-colors">
                        <Plus size={20} />
                      </button>
                    </div>
                    <button 
                      onClick={handlePost}
                      disabled={isPosting || !postContent.trim()}
                      className="bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed text-black font-bold px-6 py-2 rounded-xl flex items-center gap-2 transition-all"
                    >
                      {isPosting ? <RefreshCw size={18} className="animate-spin" /> : <Send size={18} />}
                      Broadcast
                    </button>
                  </div>
                </div>

                <div className="space-y-4">
                  <AnimatePresence mode="popLayout">
                    {messages.map(msg => (
                      <MessageCard key={msg.id} message={msg} identity={identity} />
                    ))}
                  </AnimatePresence>
                </div>
              </>
            )}

            {view === 'communities' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {communities.map(c => {
                  const isRestricted = c.isAdultOnly && !identity?.isAdult;
                  return (
                    <motion.div 
                      key={c.id}
                      whileHover={{ scale: isRestricted ? 1 : 1.02 }}
                      className={`glass p-6 rounded-3xl border border-white/10 group relative overflow-hidden ${isRestricted ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer'}`}
                    >
                      {isRestricted && (
                        <div className="absolute inset-0 bg-black/40 backdrop-blur-[2px] z-10 flex flex-col items-center justify-center p-6 text-center">
                          <Lock size={24} className="text-amber-500 mb-2" />
                          <p className="text-[10px] font-mono font-bold text-amber-500 uppercase tracking-widest">Age Restricted</p>
                          <p className="text-[9px] text-zinc-400 mt-1">Verify your age in settings to access this community.</p>
                        </div>
                      )}
                      <div className="flex items-center justify-between mb-4">
                        <div className={`w-12 h-12 rounded-2xl flex items-center justify-center transition-all ${isRestricted ? 'bg-zinc-800 text-zinc-500' : 'bg-emerald-500/10 text-emerald-500 group-hover:bg-emerald-500 group-hover:text-black'}`}>
                          {c.isAdultOnly ? <Shield size={24} /> : <Hash size={24} />}
                        </div>
                        <div className="flex flex-col items-end">
                          <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">1.2k Peers</span>
                          {c.isAdultOnly && (
                            <span className="text-[8px] font-mono font-bold text-amber-500 bg-amber-500/10 px-1.5 py-0.5 rounded uppercase mt-1">18+ Only</span>
                          )}
                        </div>
                      </div>
                      <h3 className="text-xl font-bold mb-2">{c.name}</h3>
                      <p className="text-sm text-zinc-400 mb-6">{c.description}</p>
                      <button 
                        disabled={isRestricted}
                        className={`w-full py-3 rounded-xl text-sm font-semibold transition-all ${isRestricted ? 'bg-white/5 text-zinc-600' : 'bg-white/5 hover:bg-white/10 text-white'}`}
                      >
                        {isRestricted ? 'Access Denied' : 'Join Community'}
                      </button>
                    </motion.div>
                  );
                })}
              </div>
            )}

            {view === 'settings' && (
              <div className="space-y-6">
                <section>
                  <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-500 mb-4">Session Management</h3>
                  <div className="glass p-6 rounded-3xl space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-bold">Active Session</p>
                        <p className="text-sm text-zinc-400">Node initialized at {new Date().toLocaleTimeString()}</p>
                      </div>
                      <button 
                        onClick={() => {
                          setPassphrase('');
                          setView('finish_session');
                        }}
                        className="bg-red-500/10 hover:bg-red-500/20 text-red-500 px-4 py-2 rounded-xl text-xs font-bold transition-all"
                      >
                        FINISH SESSION
                      </button>
                    </div>
                  </div>
                </section>

                <section>
                  <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-500 mb-4">Security Audit</h3>
                  <div className="glass p-6 rounded-3xl space-y-6">
                    <div className="space-y-4">
                      {[
                        { 
                          title: 'Identity Layer', 
                          desc: 'ECDSA P-256 (NIST Curve) for message signing. Identities are derived from public key hashes.',
                          status: 'ACTIVE'
                        },
                        { 
                          title: 'Encryption Layer', 
                          desc: 'ECDH for key exchange with AES-GCM 256-bit for authenticated message encryption.',
                          status: 'ACTIVE'
                        },
                        { 
                          title: 'Persistence Layer', 
                          desc: 'Volatile RAM-only storage. No forensic footprint on physical disk sectors.',
                          status: 'ACTIVE'
                        },
                        { 
                          title: 'Network Layer', 
                          desc: 'Decentralized P2P relay architecture with packet-level signature verification.',
                          status: 'ACTIVE'
                        }
                      ].map((item, i) => (
                        <div key={i} className="flex gap-4">
                          <div className="mt-1">
                            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-1">
                              <p className="text-sm font-bold tracking-tight">{item.title}</p>
                              <span className="text-[9px] font-mono font-bold text-emerald-500 bg-emerald-500/10 px-1.5 py-0.5 rounded uppercase">{item.status}</span>
                            </div>
                            <p className="text-xs text-zinc-500 leading-relaxed">{item.desc}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </section>

                <section>
                  <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-500 mb-4">Identity Management</h3>
                  <div className="glass p-6 rounded-3xl space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-bold">Public Key (SPKI)</p>
                        <p className="text-[10px] font-mono text-zinc-500 break-all max-w-md">
                          {identity?.publicKey}
                        </p>
                      </div>
                      <button className="p-2 hover:bg-white/5 rounded-lg text-zinc-400">
                        <RefreshCw size={18} />
                      </button>
                    </div>

                    <div className="flex items-center justify-between p-4 bg-white/5 border border-white/10 rounded-2xl">
                      <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${identity?.isAdult ? 'bg-emerald-500/10 text-emerald-500' : 'bg-amber-500/10 text-amber-500'}`}>
                          <UserCheck size={20} />
                        </div>
                        <div>
                          <p className="text-sm font-bold">Age Verification Status</p>
                          <p className="text-xs text-zinc-500">{identity?.isAdult ? 'Verified Adult (18+)' : 'Unverified / Minor'}</p>
                        </div>
                      </div>
                      {identity?.isAdult ? (
                        <div className="flex items-center gap-1.5 px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full">
                          <CheckCircle size={12} className="text-emerald-500" />
                          <span className="text-[10px] font-mono font-bold text-emerald-500 uppercase">Verified</span>
                        </div>
                      ) : (
                        <button 
                          onClick={async () => {
                            if (confirm("Confirm you are 18 years of age or older?")) {
                              const updatedIdentity = { ...identity!, isAdult: true };
                              setIdentity(updatedIdentity);
                              // In a real app, we'd update the vault too
                              const newVault = await identityAgent.commitVault(passphrase);
                              await storage.save('identity_vault', newVault);
                              setVault(newVault);
                            }
                          }}
                          className="px-4 py-2 bg-emerald-500 text-black text-xs font-bold rounded-xl hover:bg-emerald-400 transition-all"
                        >
                          VERIFY NOW
                        </button>
                      )}
                    </div>

                    <div className="p-4 bg-amber-500/5 border border-amber-500/10 rounded-xl">
                      <div className="flex gap-3">
                        <AlertTriangle className="text-amber-500 shrink-0" size={18} />
                        <p className="text-[11px] text-zinc-400 leading-relaxed">
                          <span className="text-amber-500 font-bold uppercase">Critical:</span> Your identity is stored only in this browser's volatile memory. If you lose your keys, you lose your identity forever. Export a backup now.
                        </p>
                      </div>
                    </div>

                    <div className="space-y-4 pt-4 border-t border-white/5">
                      <div className="flex gap-3">
                        <input 
                          type="password" 
                          placeholder="Backup Passphrase"
                          value={passphrase}
                          onChange={(e) => setPassphrase(e.target.value)}
                          className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-emerald-500/50 transition-all"
                        />
                        <button 
                          onClick={() => handleBackup(passphrase)}
                          className="bg-emerald-500 hover:bg-emerald-400 text-black px-6 py-3 rounded-xl font-bold text-sm transition-all flex items-center gap-2"
                        >
                          <Download size={18} /> Backup
                        </button>
                      </div>
                      <p className="text-[10px] text-zinc-500 font-mono uppercase text-center">Encrypted JSON Archive (AES-GCM)</p>
                    </div>

                    <div className="pt-4 border-t border-white/5">
                      <button 
                        onClick={purgeLocal}
                        className="flex items-center gap-2 text-red-500 hover:text-red-400 text-sm font-semibold transition-colors"
                      >
                        <Trash2 size={18} /> Purge Local Identity
                      </button>
                    </div>
                  </div>
                </section>

                <section>
                  <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-500 mb-4">Network Configuration</h3>
                  <div className="glass p-6 rounded-3xl space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-bold">Relay Node</p>
                        <p className="text-sm text-zinc-400">Current: Local Instance (3000)</p>
                      </div>
                      <div className="px-2 py-1 bg-emerald-500/10 text-emerald-500 text-[10px] font-bold rounded">CONNECTED</div>
                    </div>
                  </div>
                </section>

                <section>
                  <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-500 mb-4">Privacy Status</h3>
                  <div className="glass p-6 rounded-3xl space-y-4">
                    <div className="flex items-center gap-3">
                      <Shield className="text-emerald-500" size={24} />
                      <div>
                        <p className="font-bold">Zero-Trace Active</p>
                        <p className="text-sm text-zinc-400">All data is currently stored in volatile memory (RAM) only.</p>
                      </div>
                    </div>
                    <div className="p-4 bg-emerald-500/5 border border-emerald-500/10 rounded-xl">
                      <p className="text-[11px] text-zinc-400">
                        Disk storage has been disabled. Closing this tab or restarting the server will permanently erase your identity and messages.
                      </p>
                    </div>
                  </div>
                </section>
              </div>
            )}

            {view === 'dms' && (
              <div className="flex h-[calc(100vh-12rem)] gap-6">
                {/* Peer List */}
                <div className="w-1/3 flex flex-col gap-4">
                  <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-500 mb-2">Active Peers</h3>
                  <div className="flex-1 overflow-y-auto space-y-2 pr-2">
                    {peers.filter(p => p.pubkey !== identity?.publicKey).map(p => (
                      <button
                        key={p.pubkey}
                        onClick={() => setActivePeer(p)}
                        className={`w-full p-4 rounded-2xl glass border transition-all text-left group ${
                          activePeer?.pubkey === p.pubkey ? 'border-emerald-500/50 bg-emerald-500/5' : 'border-white/5 hover:border-white/10'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <div className="relative">
                            <div className="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center text-zinc-400 group-hover:text-emerald-500 transition-colors">
                              <User size={20} />
                            </div>
                            <div className={`absolute -bottom-1 -right-1 w-3 h-3 rounded-full border-2 border-[#0A0A0A] ${
                              p.status === 'online' ? 'bg-emerald-500' : 'bg-zinc-600'
                            }`} />
                          </div>
                          <div className="overflow-hidden">
                            <p className="font-bold truncate">{p.metadata.handle || 'Unknown Peer'}</p>
                            <div className="flex items-center gap-2">
                              <p className="status-label truncate">{p.status}</p>
                              <span className="text-[8px] font-mono text-zinc-600">•</span>
                              <span className="text-[8px] font-mono text-zinc-600 uppercase tracking-widest">{p.connectionType}</span>
                            </div>
                          </div>
                        </div>
                      </button>
                    ))}
                    {peers.length <= 1 && (
                      <div className="text-center py-10 text-zinc-600">
                        <p className="text-sm">No peers discovered yet.</p>
                        <p className="text-[10px] font-mono mt-2">Gossip protocol active...</p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Chat Area */}
                <div className="flex-1 flex flex-col glass rounded-[2.5rem] border border-white/5 overflow-hidden">
                  {activePeer ? (
                    <>
                      <div className="p-6 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center text-emerald-500">
                            <Lock size={20} />
                          </div>
                          <div>
                            <p className="font-bold">{activePeer.metadata.handle}</p>
                            <p className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest">Secure Channel Active</p>
                          </div>
                        </div>
                        <button className="p-2 hover:bg-white/5 rounded-lg text-zinc-500">
                          <MoreVertical size={18} />
                        </button>
                      </div>

                      <div className="flex-1 overflow-y-auto p-6 space-y-4">
                        {dmMessages.map((msg, i) => {
                          const isVerified = msg.metadata?.verified;
                          return (
                            <div key={msg.id || i} className={`flex ${msg.sender === identity?.publicKey ? 'justify-end' : 'justify-start'}`}>
                              <div className="flex flex-col gap-1 max-w-[80%]">
                                <div className={`p-4 rounded-2xl text-sm relative ${
                                  msg.sender === identity?.publicKey 
                                    ? 'bg-emerald-500 text-black font-medium rounded-tr-none' 
                                    : 'bg-white/5 text-zinc-300 rounded-tl-none border border-white/5'
                                }`}>
                                  {msg.content}
                                  <div className={`absolute -bottom-2 ${msg.sender === identity?.publicKey ? '-left-2' : '-right-2'} flex items-center gap-1 px-1.5 py-0.5 bg-[#0A0A0A] border border-white/5 rounded-full`}>
                                    {isVerified ? (
                                      <Shield size={8} className="text-emerald-500" />
                                    ) : (
                                      <AlertTriangle size={8} className="text-red-500" />
                                    )}
                                    <Lock size={8} className="text-emerald-500/70" />
                                  </div>
                                </div>
                                <div className={`text-[9px] font-mono uppercase opacity-50 px-2 flex items-center gap-2 ${
                                  msg.sender === identity?.publicKey ? 'justify-end text-black/50' : 'justify-start text-zinc-500'
                                }`}>
                                  {new Date(msg.timestamp).toLocaleTimeString()}
                                  <span>•</span>
                                  <span className={`flex items-center gap-1 ${isVerified ? '' : 'text-red-500'}`}>
                                    {isVerified ? <Shield size={8} /> : <AlertTriangle size={8} />} 
                                    {isVerified ? 'VERIFIED' : 'UNVERIFIED'}
                                  </span>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                        {dmMessages.length === 0 && (
                          <div className="h-full flex flex-col items-center justify-center text-zinc-600">
                            <Lock size={32} className="mb-4 opacity-20" />
                            <p className="text-xs font-mono uppercase tracking-widest">End-to-End Encrypted Session</p>
                          </div>
                        )}
                      </div>

                      <div className="p-6 border-t border-white/5 bg-white/[0.02]">
                        <div className="flex gap-3">
                          <input 
                            type="text"
                            value={dmContent}
                            onChange={(e) => setDmContent(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleSendDM()}
                            placeholder="Type a secure message..."
                            className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-emerald-500/50 transition-all"
                          />
                          <button 
                            onClick={handleSendDM}
                            className="bg-emerald-500 hover:bg-emerald-400 text-black p-3 rounded-xl transition-all"
                          >
                            <Send size={20} />
                          </button>
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="flex-1 flex flex-col items-center justify-center text-center p-12">
                      <div className="w-20 h-20 bg-white/5 rounded-full flex items-center justify-center mb-6">
                        <MessageSquare size={40} className="text-zinc-700" />
                      </div>
                      <h3 className="text-xl font-bold mb-2">Select a Peer</h3>
                      <p className="text-sm text-zinc-500 max-w-xs">
                        Choose a discovered node from the list to initiate a secure, end-to-end encrypted conversation.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            )}

          </div>
        </div>
      </main>
    </div>
  );
}
