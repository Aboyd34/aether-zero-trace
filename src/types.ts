/**
 * Aether Architectural Specification
 * 
 * 1. OVERVIEW
 * Aether is a decentralized social layer. It operates as a collection of local agents
 * that manage identity, cryptography, and data synchronization.
 * 
 * 2. MODULES
 * - PrivacyAgent: Handles RSA/ECDSA key generation and WebCrypto operations.
 * - IdentityAgent: Manages user profiles (pseudonyms) and links them to keys.
 * - RelayAgent: Manages the "network" interface, packetizing data for transport.
 * - DiscoveryAgent: Handles community joining and peer discovery logic.
 * - StorageAgent: Interfaces with the local SQLite database for persistence.
 * - ModerationAgent: Applies local filters to incoming content.
 * 
 * 3. DATA FLOW
 * [User Input] -> [IdentityAgent] -> [PrivacyAgent (Sign)] -> [RelayAgent (Packetize)] -> [Network]
 * [Network] -> [RelayAgent (Depacketize)] -> [PrivacyAgent (Verify)] -> [ModerationAgent] -> [StorageAgent] -> [UI]
 * 
 * 4. THREAT MODEL
 * - Content Tampering: Mitigated by ECDSA signatures on every message.
 * - Identity Spoofing: Mitigated by linking handles to Public Keys.
 * - Surveillance: Mitigated by E2EE for DMs and lack of central indexing.
 */

export interface AetherVault {
  encryptedIdentities: string; // AES-GCM encrypted JSON string of AetherIdentity[]
  iv: string;
  salt: string;
}

export interface AetherIdentity {
  id: string; // Hash of public key
  handle: string;
  avatar?: string;
  publicKey: string;
  privateKey?: string; // Only stored locally
  encryptionPublicKey: string;
  encryptionPrivateKey?: string; // Only stored locally
  isAdult?: boolean; // Age verification status
}

export interface AetherMessage {
  id: string;
  topic: string; // "global", "community:xyz", "dm:pubkey"
  sender: string; // PubKey
  content: string; // Encrypted or Plaintext
  signature: string;
  timestamp: number;
  type: 'post' | 'reply' | 'dm';
  iv?: string; // Initialization Vector for AES-GCM
  metadata?: Record<string, any>;
}

export interface AetherPacket {
  header: {
    version: string;
    type: string;
    recipient?: string; // For DMs
    isEncrypted?: boolean;
    iv?: string; // If encrypted at packet level
    ephemeralPublicKey?: string; // For ECDH key exchange
  };
  payload: string; // JSON string of AetherMessage (possibly encrypted)
  signature: string;
}

export interface AetherPeer {
  pubkey: string;
  lastSeen: number;
  status: 'online' | 'offline';
  connectionType: 'direct' | 'relay';
  metadata: Record<string, any>;
}

export interface AetherCommunity {
  id: string;
  name: string;
  description: string;
  owner_pubkey: string;
  created_at: number;
}
