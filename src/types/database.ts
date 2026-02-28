export interface StorageEntry {
  key: string;
  value: string;
}

export interface Message {
  id: string;
  topic: string;
  sender_pubkey: string;
  payload: string;
  signature: string;
  timestamp: number;
}

export interface Peer {
  pubkey: string;
  last_seen: number;
  status: 'online' | 'offline' | 'away';
  connection_type: 'direct' | 'relay';
  metadata: Record<string, any>;
}

export interface Community {
  id: string;
  name: string;
  description: string;
  owner_pubkey: string;
  created_at: number;
}
