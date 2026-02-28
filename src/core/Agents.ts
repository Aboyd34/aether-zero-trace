import { AetherIdentity, AetherMessage, AetherVault } from "../types";

/**
 * Privacy Agent: The cryptographic core.
 * Handles key generation, signing, and encryption.
 */
export class PrivacyAgent {
  private static instance: PrivacyAgent;
  private keyPair: CryptoKeyPair | null = null;

  private constructor() {}

  static getInstance() {
    if (!this.instance) this.instance = new PrivacyAgent();
    return this.instance;
  }

  // Vault Derivation (PBKDF2)
  async deriveVaultKey(passphrase: string, saltB64: string): Promise<CryptoKey> {
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const encoder = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
      "raw",
      encoder.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async encryptVault(identities: AetherIdentity[], passphrase: string): Promise<AetherVault> {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = btoa(String.fromCharCode(...salt));
    const key = await this.deriveVaultKey(passphrase, saltB64);
    
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(identities));

    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );

    return {
      encryptedIdentities: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
      iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
      salt: saltB64
    };
  }

  async decryptVault(vault: AetherVault, passphrase: string): Promise<AetherIdentity[]> {
    const key = await this.deriveVaultKey(passphrase, vault.salt);
    const iv = Uint8Array.from(atob(vault.iv), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob(vault.encryptedIdentities), c => c.charCodeAt(0));

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
  }

  async generateIdentityKeys(): Promise<{ publicKey: string; privateKey: string; encryptionPublicKey: string; encryptionPrivateKey: string }> {
    // ECDSA for Signing
    const signingKeys = await window.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );

    // ECDH for Encryption
    const encryptionKeys = await window.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );

    const pubExport = await window.crypto.subtle.exportKey("spki", signingKeys.publicKey);
    const privExport = await window.crypto.subtle.exportKey("pkcs8", signingKeys.privateKey);
    const encPubExport = await window.crypto.subtle.exportKey("spki", encryptionKeys.publicKey);
    const encPrivExport = await window.crypto.subtle.exportKey("pkcs8", encryptionKeys.privateKey);

    return {
      publicKey: btoa(String.fromCharCode(...new Uint8Array(pubExport))),
      privateKey: btoa(String.fromCharCode(...new Uint8Array(privExport))),
      encryptionPublicKey: btoa(String.fromCharCode(...new Uint8Array(encPubExport))),
      encryptionPrivateKey: btoa(String.fromCharCode(...new Uint8Array(encPrivExport))),
    };
  }

  async signMessage(message: string, privateKeyB64: string): Promise<string> {
    const privBuffer = Uint8Array.from(atob(privateKeyB64), c => c.charCodeAt(0));
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      privBuffer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );

    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const signature = await window.crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      key,
      data
    );

    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  }

  async verifySignature(message: string, signatureB64: string, publicKeyB64: string): Promise<boolean> {
    try {
      const pubBuffer = Uint8Array.from(atob(publicKeyB64), c => c.charCodeAt(0));
      const sigBuffer = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
      
      const key = await window.crypto.subtle.importKey(
        "spki",
        pubBuffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      );

      const encoder = new TextEncoder();
      const data = encoder.encode(message);
      
      return await window.crypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        key,
        sigBuffer,
        data
      );
    } catch (e) {
      return false;
    }
  }

  // E2EE for DMs (AES-GCM with ECDH)
  async encryptForPeer(text: string, peerEncPubKeyB64: string, myEncPrivKeyB64: string): Promise<{ cipher: string; iv: string }> {
    const myPrivBuffer = Uint8Array.from(atob(myEncPrivKeyB64), c => c.charCodeAt(0));
    const peerPubBuffer = Uint8Array.from(atob(peerEncPubKeyB64), c => c.charCodeAt(0));

    const myPrivKey = await window.crypto.subtle.importKey(
      "pkcs8",
      myPrivBuffer,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
    );

    const peerPubKey = await window.crypto.subtle.importKey(
      "spki",
      peerPubBuffer,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    const sharedKey = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPubKey },
      myPrivKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    const cipher = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      sharedKey,
      data
    );

    return {
      cipher: btoa(String.fromCharCode(...new Uint8Array(cipher))),
      iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
    };
  }

  async decryptFromPeer(cipherB64: string, ivB64: string, peerEncPubKeyB64: string, myEncPrivKeyB64: string): Promise<string> {
    const myPrivBuffer = Uint8Array.from(atob(myEncPrivKeyB64), c => c.charCodeAt(0));
    const peerPubBuffer = Uint8Array.from(atob(peerEncPubKeyB64), c => c.charCodeAt(0));
    const cipherBuffer = Uint8Array.from(atob(cipherB64), c => c.charCodeAt(0));
    const ivBuffer = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));

    const myPrivKey = await window.crypto.subtle.importKey(
      "pkcs8",
      myPrivBuffer,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
    );

    const peerPubKey = await window.crypto.subtle.importKey(
      "spki",
      peerPubBuffer,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    const sharedKey = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPubKey },
      myPrivKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBuffer },
      sharedKey,
      cipherBuffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  // Secure Wipe Memory
  async secureWipeMemory() {
    this.keyPair = null;
    // In JS, we can't force GC or zero memory, but we can nullify references
    // and hope the engine clears them.
  }
}

/**
 * Identity Agent: Manages pseudonyms.
 */
export class IdentityAgent {
  private static instance: IdentityAgent;
  private identities: AetherIdentity[] = [];
  private isUnlocked: boolean = false;

  private constructor() {}

  static getInstance() {
    if (!this.instance) this.instance = new IdentityAgent();
    return this.instance;
  }

  async unlockVault(vault: AetherVault, passphrase: string): Promise<AetherIdentity[]> {
    const privacy = PrivacyAgent.getInstance();
    try {
      this.identities = await privacy.decryptVault(vault, passphrase);
      this.isUnlocked = true;
      return this.identities;
    } catch (e) {
      this.isUnlocked = false;
      this.identities = [];
      throw new Error("Failed to unlock vault: Invalid passphrase.");
    }
  }

  async createIdentity(handle: string, isAdult: boolean = false): Promise<AetherIdentity> {
    const privacy = PrivacyAgent.getInstance();
    const { publicKey, privateKey, encryptionPublicKey, encryptionPrivateKey } = await privacy.generateIdentityKeys();
    
    const identity: AetherIdentity = {
      id: publicKey.slice(0, 16),
      handle,
      publicKey,
      privateKey,
      encryptionPublicKey,
      encryptionPrivateKey,
      isAdult,
    };

    this.identities.push(identity);
    return identity;
  }

  async commitVault(passphrase: string): Promise<AetherVault> {
    const privacy = PrivacyAgent.getInstance();
    return await privacy.encryptVault(this.identities, passphrase);
  }

  getIdentities(): AetherIdentity[] {
    if (!this.isUnlocked && this.identities.length === 0) {
      throw new Error("Identity vault is locked.");
    }
    return this.identities;
  }

  lock() {
    this.identities = [];
    this.isUnlocked = false;
  }

  async signChallenge(challenge: string, identity: AetherIdentity): Promise<string> {
    const privacy = PrivacyAgent.getInstance();
    if (!identity.privateKey) throw new Error("Private key missing for signing.");
    return await privacy.signMessage(challenge, identity.privateKey);
  }

  async verifyChallenge(challenge: string, signature: string, publicKey: string): Promise<boolean> {
    const privacy = PrivacyAgent.getInstance();
    return await privacy.verifySignature(challenge, signature, publicKey);
  }
}

/**
 * Relay Agent: Network transport.
 */
export class RelayAgent {
  async broadcast(message: AetherMessage) {
    await fetch("/api/relay/broadcast", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message),
    });
  }

  async sendDirectMessage(message: AetherMessage, recipientPubKey: string) {
    // In a real P2P network, this would route directly or via specific relays
    // For this implementation, we use the relay with a recipient header
    const packet = {
      header: {
        version: "1.0",
        type: "dm",
        recipient: recipientPubKey,
      },
      payload: JSON.stringify(message),
      signature: message.signature
    };

    await fetch("/api/relay/broadcast", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...message, topic: `dm:${recipientPubKey}` }),
    });
  }

  async fetchFeed(): Promise<AetherMessage[]> {
    const res = await fetch("/api/relay/feed");
    return res.json();
  }

  async fetchTopic(topic: string): Promise<AetherMessage[]> {
    const res = await fetch(`/api/relay/messages/${topic}`);
    return res.json();
  }
}

/**
 * Storage Agent: Local persistence and data lifecycle.
 */
export class StorageAgent {
  // Generic KV Store
  async save(key: string, value: any) {
    await fetch("/api/storage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, value }),
    });
  }

  async load(key: string): Promise<any> {
    const res = await fetch(`/api/storage/${key}`);
    const data = await res.json();
    return data.value;
  }

  // Community CRUD
  async saveCommunity(community: { id: string, name: string, description: string, owner_pubkey: string }) {
    await fetch("/api/communities", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(community),
    });
  }

  async deleteCommunity(id: string) {
    await fetch(`/api/communities/${id}`, { method: "DELETE" });
  }

  // Peer Management
  async savePeer(peer: { 
    pubkey: string, 
    lastSeen: number, 
    status: 'online' | 'offline', 
    connectionType: 'direct' | 'relay', 
    metadata: Record<string, any> 
  }) {
    await fetch("/api/peers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(peer),
    });
  }

  async getPeers(): Promise<any[]> {
    const res = await fetch("/api/peers");
    return res.json();
  }

  async deletePeer(pubkey: string) {
    await fetch(`/api/peers/${pubkey}`, { method: "DELETE" });
  }

  // Retention Logic
  async applyRetentionPolicy(policy: { maxAgeMs?: number, maxCount?: number }) {
    await fetch("/api/storage/maintenance/retention", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(policy),
    });
  }

  async fullPurge() {
    await fetch("/api/storage/maintenance/purge", { method: "POST" });
    localStorage.clear();
  }

  // Full Data Dump and Secure Wipe
  async exportDataDump(passphrase: string): Promise<string> {
    const res = await fetch("/api/storage/dump");
    const data = await res.json();
    
    const privacy = PrivacyAgent.getInstance();
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = btoa(String.fromCharCode(...salt));
    const key = await privacy.deriveVaultKey(passphrase, saltB64);
    
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const payload = encoder.encode(JSON.stringify(data));

    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      payload
    );

    const archive = {
      data: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
      iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
      salt: saltB64,
      timestamp: Date.now(),
      version: "1.0"
    };

    return JSON.stringify(archive);
  }

  async secureWipe() {
    // 1. Clear memory
    const privacy = PrivacyAgent.getInstance();
    await privacy.secureWipeMemory();

    // 2. Clear backend (in-memory SQLite)
    await fetch("/api/storage/maintenance/purge", { method: "POST" });

    // 3. Clear local storage
    localStorage.clear();
    
    // 4. Force reload to clear remaining memory state
    window.location.reload();
  }
}

/**
 * Discovery Agent: Community management and peer discovery.
 * Implements a Gossip-based discovery protocol.
 */
export class DiscoveryAgent {
  private relay = new RelayAgent();
  private storage = new StorageAgent();

  async announcePresence(identity: AetherIdentity) {
    const presenceMsg: AetherMessage = {
      id: `presence_${Math.random().toString(36).slice(2)}`,
      topic: "discovery",
      sender: identity.publicKey,
      content: JSON.stringify({
        handle: identity.handle,
        encryptionPublicKey: identity.encryptionPublicKey,
        status: 'online',
        connectionType: 'relay'
      }),
      signature: "PRESENCE_SIG", // Simplified for discovery
      timestamp: Date.now(),
      type: 'post'
    };
    await this.relay.broadcast(presenceMsg);
  }

  async discoverPeers(): Promise<void> {
    const messages = await this.relay.fetchTopic("discovery");
    for (const msg of messages) {
      try {
        const data = JSON.parse(msg.content);
        await this.storage.savePeer({
          pubkey: msg.sender,
          lastSeen: msg.timestamp,
          status: 'online',
          connectionType: 'relay',
          metadata: {
            handle: data.handle,
            encryptionPublicKey: data.encryptionPublicKey
          }
        });
      } catch (e) {
        // Invalid presence packet
      }
    }
  }

  async getCommunities(): Promise<any[]> {
    const res = await fetch("/api/communities");
    const data = await res.json();
    
    // Fallback to defaults if none exist
    if (data.length === 0) {
      return [
        { id: "global", name: "Global Square", description: "The public square of Aether." },
        { id: "privacy", name: "Privacy Tech", description: "Discussions on cryptography and anonymity." },
        { id: "dev", name: "Developers", description: "Building the decentralized future." },
        { id: "adult", name: "After Dark", description: "Age-restricted discussions. 18+ only.", isAdultOnly: true },
      ];
    }
    return data;
  }
}

/**
 * Moderation Agent: Local filtering.
 */
export class ModerationAgent {
  private blockedKeys: Set<string> = new Set();

  block(pubKey: string) {
    this.blockedKeys.add(pubKey);
  }

  filter(messages: AetherMessage[]): AetherMessage[] {
    return messages.filter(m => !this.blockedKeys.has(m.sender));
  }
}
