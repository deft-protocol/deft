# DEFT Protocol - Spécification Fonctionnelle v0.1

**Delta-Enabled File Transfer**

*Date: 19 Janvier 2026*  
*Version: 0.1 (Draft)*

---

## 1. Vue d'ensemble

### 1.1 Objectif

DEFT est un protocole moderne de transfert de fichiers conçu pour les échanges B2B (Business-to-Business). Il combine la simplicité architecturale de FTP avec des concepts avancés inspirés de PESIT (fichiers virtuels, partenaires) et BitTorrent (chunks, vérification d'intégrité).

### 1.2 Principes de conception

- **Sécurité par défaut** : mTLS obligatoire, pas de fallback en clair
- **Fiabilité** : mécanismes de reprise granulaire avec validation d'intégrité
- **Performance** : support du transfert parallèle sur multiples interfaces réseau
- **Simplicité** : protocole textuel lisible, facile à implémenter et déboguer
- **Abstraction** : séparation entre fichiers virtuels (logique) et fichiers physiques (stockage)

### 1.3 Cas d'usage typiques

- Échange de factures, commandes, fichiers EDI entre entreprises
- Transfert de dumps de bases de données
- Distribution de catalogues produits à des partenaires
- Archivage et synchronisation de données volumineuses

---

## 2. Concepts fondamentaux

### 2.1 Partenaires

Un **partenaire** est une entité business identifiée de manière unique, authentifiée via certificat client (mTLS). Chaque partenaire possède :

- Un identifiant unique (`partner-id`)
- Un certificat X.509 pour l'authentification
- Des permissions d'accès à des fichiers virtuels spécifiques

### 2.2 Fichiers virtuels

Un **fichier virtuel** est une abstraction logique représentant un fichier ou un flux de données. Il possède :

- Un nom logique indépendant du stockage physique (ex: `monthly-invoices`)
- Des métadonnées (taille, date, checksums)
- Un mapping vers un ou plusieurs fichiers physiques
- Des règles d'accès par partenaire

**Avantages** :
- Découplage entre identification logique et stockage
- Contrôle d'accès granulaire
- Versionning et historique possibles
- Facilite les migrations de stockage

### 2.3 Chunks et intégrité

Inspiré de BitTorrent, chaque fichier est découpé en **chunks** de taille fixe (ex: 256 KB). Chaque chunk possède :

- Un index séquentiel
- Un hash cryptographique (SHA-256)
- Une taille (fixe sauf dernier chunk)

**Bénéfices** :
- Reprise granulaire en cas d'interruption
- Validation d'intégrité immédiate (pas besoin d'attendre la fin du transfert)
- Parallélisation du transfert
- Détection précoce de corruption

### 2.4 Transfert parallèle

Le serveur peut exposer plusieurs endpoints réseau (IPs multiples). Le client peut :

- Télécharger différents chunks simultanément via différentes connexions
- Utiliser plusieurs interfaces réseau pour agréger la bande passante
- Continuer le transfert si une route/interface tombe

---

## 3. Architecture du protocole

### 3.1 Modèle peer-to-peer symétrique

DEFT utilise une architecture peer où chaque instance peut agir simultanément comme client et serveur. Cette approche unifiée reflète la réalité des échanges B2B bidirectionnels.

**Caractéristiques** :
- Un seul daemon par entreprise/partenaire
- Peut recevoir des connexions entrantes (mode serveur)
- Peut initier des connexions sortantes (mode client)
- Configuration unifiée des partenaires et fichiers virtuels
- Traçabilité et audit maintenus dans les deux directions

**Avantages** :
- Simplicité opérationnelle : un seul binaire à déployer et maintenir
- Échanges naturellement bidirectionnels (A ↔ B)
- Tous les partenaires sont égaux, pas de hiérarchie artificielle
- Configuration centralisée

**Sécurité** :
- Le mode serveur peut être désactivé si non nécessaire
- Même niveau de sécurité (mTLS) dans les deux directions
- Principe du moindre privilège maintenu via les permissions par partenaire

### 3.2 Canal de contrôle

Connexion TCP persistante sur le port **7741** (DEFT en leet speak) :

- Protocole textuel (commandes ASCII)
- Multiplexage des commandes et réponses
- Session authentifiée et chiffrée (TLS 1.3)

### 3.3 Canaux de données

Connexions séparées pour le transfert des chunks :

- Peuvent être multiples et parallèles
- Chiffrées (TLS)
- Optimisées pour le débit (moins de latence que le canal de contrôle)

---

## 4. Sécurité

### 4.1 Transport Layer Security

- **TLS 1.3 minimum** obligatoire
- **mTLS (Mutual TLS)** : authentification client et serveur par certificats
- Pas de mode "clair" ou dégradé
- Cipher suites modernes uniquement

### 4.2 Authentification

- Certificat client X.509 validé côté serveur
- Le `partner-id` doit correspondre au CN ou SAN du certificat
- Pas de système de mot de passe (redondant avec mTLS)

### 4.3 Autorisation

- Modèle par liste blanche : association explicite partenaire ↔ fichiers virtuels
- Principe du moindre privilège
- Journalisation de tous les accès

### 4.4 Intégrité

- Hash SHA-256 de chaque chunk
- Hash global du fichier complet
- Validation à la réception de chaque chunk
- Rejet immédiat en cas de non-correspondance

---

## 5. Fonctionnalités principales

### 5.1 Découverte

Le client peut lister les fichiers virtuels auxquels il a accès :

- Liste des noms de fichiers virtuels
- Métadonnées associées (taille, date de modification, etc.)
- Permissions (lecture/écriture)

### 5.2 Transfert avec reprise et accusés de réception

DEFT utilise un système d'accusés de réception asynchrones pour garantir la fiabilité sans sacrifier la performance.

**Modèle de fenêtre glissante :**
- Le client peut envoyer plusieurs chunks sans attendre l'accusé de chacun
- Taille de fenêtre négociée au handshake (nombre de chunks en vol maximum)
- Le serveur envoie des accusés asynchrones au fur et à mesure de la validation
- Évite le goulet d'étranglement du modèle synchrone (attente d'ACK entre chaque chunk)

**Types d'accusés :**

1. **Accusés par chunk (CHUNK_ACK)** :
   - Envoyés par le serveur après validation du hash de chaque chunk
   - Asynchrones et potentiellement groupés pour optimiser
   - Permettent au client de libérer sa fenêtre de transmission

2. **Accusé final de transfert (TRANSFER_COMPLETE)** :
   - Envoyé quand tous les chunks sont reçus et le fichier complet validé
   - Contient le hash du fichier complet, la taille totale, le nombre de chunks
   - Sert de preuve de livraison pour non-répudiation

**Mécanisme de reprise :**
- Récupération des métadonnées avant transfert (liste des chunks, hashs)
- Téléchargement chunk par chunk avec validation immédiate
- En cas d'interruption : reprise depuis le dernier chunk validé
- Timeout et retransmission automatique des chunks non accusés
- Pas de retransmission des chunks déjà reçus et validés

**Gestion des erreurs :**
- Si un chunk échoue la validation (hash incorrect), ACK avec code erreur
- Le client retransmet uniquement les chunks en erreur
- Après N tentatives échouées, abandon du transfert avec notification

### 5.3 Parallélisation

- Négociation des capacités au handshake (`PARALLEL`)
- Découverte des endpoints multiples
- Distribution des chunks sur plusieurs connexions
- Agrégation de bande passante

### 5.4 Traçabilité et non-répudiation

DEFT fournit une traçabilité complète et des preuves de transfert pour l'audit et la conformité :

**Logs et audit trail :**
- Session ID unique par connexion
- Logs structurés de toutes les opérations (connexion, authentification, transferts)
- Métriques de performance (débit, latence, chunks transférés)
- Horodatage précis de chaque événement

**Preuves de transfert :**
- Accusés de réception signés cryptographiquement (optionnel)
- Stockage immuable des accusés finaux (append-only log)
- Hash complet du fichier transféré
- Métadonnées : émetteur, destinataire, timestamp, taille

**Format de preuve de livraison :**
```json
{
  "transfer_id": "uuid-1234-5678",
  "virtual_file": "invoices-january-2026",
  "sender_partner": "acme-corp",
  "receiver_partner": "supplier-inc",
  "timestamp_start": "2026-01-19T14:30:00Z",
  "timestamp_complete": "2026-01-19T14:35:23Z",
  "chunks_total": 400,
  "total_bytes": 104857600,
  "file_hash": "sha256:abc123...",
  "signature": "..." 
}
```

Ces preuves permettent la conformité réglementaire et la résolution de litiges.

---

## 6. Comparaison avec les protocoles existants

| Fonctionnalité | FTP/SFTP | PESIT | AS2 | DEFT |
|----------------|----------|-------|-----|------|
| Sécurité moderne (mTLS) | Partiel | Non | Oui | Oui |
| Fichiers virtuels | Non | Oui | Non | Oui |
| Gestion partenaires | Non | Oui | Oui | Oui |
| Reprise granulaire | Non | Oui | Non | Oui |
| Transfert parallèle | Non | Non | Non | Oui |
| Vérification intégrité | Basique | Oui | Oui | Oui (chunks) |
| Simplicité | Haute | Moyenne | Faible | Haute |
| Modernité | Moyenne | Faible | Moyenne | Haute |

---

## 7. Inspirations et crédits

DEFT s'inspire de plusieurs protocoles éprouvés :

- **FTP** : architecture canal de contrôle/données
- **PESIT** : concepts de partenaires et fichiers virtuels
- **BitTorrent** : découpage en chunks, hashes, robustesse
- **HTTP/2** : multiplexing, efficacité du protocole

---

## 8. Implémentation de référence

L'implémentation de référence sera développée en **Rust** pour :

- Performance native
- Sécurité mémoire
- Concurrence sans data races
- Déploiement simplifié (binaires standalone)

**Composants** :
- `deft-protocol` : définitions du protocole
- `deft-daemon` : daemon unifié (serveur + client)
- `deft-cli` : interface en ligne de commande pour contrôler le daemon
- `deft-common` : utilitaires partagés (chunking, hashing)

---

## 9. Roadmap

### Phase 1 : POC (Proof of Concept)
- Handshake et authentification
- Transfert basique d'un fichier avec chunks
- Validation des hashs

### Phase 2 : Fonctionnalités core
- Découverte de fichiers virtuels
- Reprise sur erreur
- Configuration partenaires/VF

### Phase 3 : Performance
- Transfert parallèle
- Multi-endpoints
- Optimisations réseau

### Phase 4 : Production
- Logging et monitoring
- Métriques et dashboards
- Documentation complète
- Tests de charge

---

## 10. Architecture peer unifiée

### 10.1 Daemon DEFT

Chaque instance DEFT est un daemon unique capable d'agir comme client et serveur simultanément :

```
deftd --config /etc/deft/config.toml
```

### 10.2 Configuration unifiée

Exemple de fichier de configuration :

```toml
[server]
enabled = true                    # Accepter les connexions entrantes
listen = "0.0.0.0:7741"
cert = "/etc/deft/certs/server.crt"
key = "/etc/deft/certs/server.key"
ca = "/etc/deft/certs/ca.crt"    # CA pour valider certificats clients

[client]
enabled = true                    # Autoriser les connexions sortantes
cert = "/etc/deft/certs/client.crt"
key = "/etc/deft/certs/client.key"
ca = "/etc/deft/certs/ca.crt"    # CA pour valider certificats serveurs

# Définition des partenaires
[[partners]]
id = "supplier-inc"
# Certificats autorisés pour ce partenaire (connexions entrantes)
allowed_certs = ["/etc/deft/partners/supplier.crt"]
# Adresses pour connexions sortantes vers ce partenaire
endpoints = ["supplier.example.com:7741"]

# Fichiers virtuels accessibles par ce partenaire
[[partners.virtual_files]]
name = "orders-outbound"
path = "/data/orders/*.xml"
direction = "send"               # Ce partenaire peut récupérer (nous envoyons)

[[partners.virtual_files]]
name = "invoices-inbound"
path = "/data/invoices/"
direction = "receive"            # Ce partenaire peut envoyer (nous recevons)

[[partners]]
id = "customer-acme"
allowed_certs = ["/etc/deft/partners/acme.crt"]
endpoints = ["acme.example.com:7741", "acme-backup.example.com:7741"]

[[partners.virtual_files]]
name = "product-catalog"
path = "/data/catalog/current.json"
direction = "send"

[storage]
chunk_size = 262144              # 256 KB
temp_dir = "/var/deft/tmp"
```

### 10.3 Modes de fonctionnement

**Mode serveur uniquement** :
```toml
[server]
enabled = true
[client]
enabled = false
```

**Mode client uniquement** :
```toml
[server]
enabled = false
[client]
enabled = true
```

**Mode peer (recommandé pour B2B)** :
```toml
[server]
enabled = true
[client]
enabled = true
```

### 10.4 Scénarios d'échange

**Scénario 1 : Push (entreprise A envoie à B)**
```
A (client) → B (serveur)
1. A se connecte à B
2. A s'authentifie comme partenaire
3. A pousse le fichier virtuel vers B
```

**Scénario 2 : Pull (entreprise B récupère depuis A)**
```
B (client) → A (serveur)
1. B se connecte à A
2. B s'authentifie comme partenaire
3. B tire le fichier virtuel depuis A
```

**Scénario 3 : Bidirectionnel**
```
Session 1: A → B (A envoie commandes)
Session 2: B → A (B envoie factures)

Ou dans la même session :
A ↔ B : échange mutuel selon permissions
```

### 10.5 Traçabilité bidirectionnelle

Dans l'architecture peer, chaque instance DEFT maintient :
- Logs des connexions entrantes (mode serveur)
- Logs des connexions sortantes (mode client)
- Preuves de livraison pour les transferts dans les deux sens
- Corrélation via transfer_id unique

---

## 11. Protocole d'accusés de réception

### 11.1 Principe de fenêtre glissante

Pour optimiser la performance, DEFT utilise un modèle asynchrone inspiré du contrôle de flux TCP :

**Fenêtre de transmission :**
- Nombre maximum de chunks pouvant être en vol simultanément
- Négocié au handshake entre client et serveur
- Le client peut continuer d'envoyer tant que la fenêtre n'est pas pleine
- Chaque ACK reçu libère un slot dans la fenêtre

**Exemple de flux :**
```
t0: Client envoie chunks 1,2,3,4,5 (fenêtre=5, pleine)
t1: Server valide et ACK chunk 1
t2: Client reçoit ACK 1, fenêtre libérée → envoie chunk 6
t3: Server valide et ACK chunks 2,3
t4: Client reçoit ACK 2,3 → envoie chunks 7,8
...
```

**Avantages :**
- Pas de latence RTT entre chaque chunk (vs modèle synchrone)
- Pipeline de transmission maintenu constamment rempli
- Débit optimal même sur liens à haute latence
- Le serveur contrôle sa charge via la taille de fenêtre

### 11.2 Commandes d'accusé de réception

**ACK individuel par chunk :**
```
DEFT CHUNK_ACK <virtual-file> <chunk-index> <status> [<reason>]

Exemples :
DEFT CHUNK_ACK invoices-jan 42 OK
DEFT CHUNK_ACK invoices-jan 43 ERROR HASH_MISMATCH
DEFT CHUNK_ACK invoices-jan 44 ERROR TIMEOUT
```

**ACK groupé (optimisation) :**
```
DEFT CHUNK_ACK_BATCH <virtual-file> <chunk-ranges>

Exemple :
DEFT CHUNK_ACK_BATCH invoices-jan 1-50,52-100,105-200

Indique que les chunks 1 à 50, 52 à 100, et 105 à 200 sont OK
Les chunks 51, 101-104 sont implicitement en erreur ou manquants
```

**Accusé final de transfert :**
```
DEFT TRANSFER_COMPLETE <virtual-file> <file-hash> <total-size> <chunk-count> [<signature>]

Exemple :
DEFT TRANSFER_COMPLETE invoices-jan sha256:abc123def456... 104857600 400 sig:xyz789...
```

### 11.3 Négociation de fenêtre au handshake

La taille de fenêtre est négociée lors du HELLO :

```
Client → Server:
DEFT HELLO 1.0 CHUNKED,PARALLEL,RESUME WINDOW_SIZE:128

Server → Client:
DEFT WELCOME 1.0 CHUNKED,PARALLEL,RESUME WINDOW_SIZE:64 sess_xyz
```

Le serveur peut :
- Accepter la fenêtre proposée (128)
- Réduire à une taille plus conservative (64)
- Refuse jamais d'augmenter au-delà de sa capacité

La fenêtre effective est le **minimum** des deux valeurs.

### 11.4 Gestion des chunks manquants et retransmission

**Détection de perte :**
- Timeout par chunk (ex: 10 secondes sans ACK)
- Le client track les chunks envoyés vs accusés
- Si timeout expiré, considéré comme perdu

**Stratégie de retransmission :**
```rust
// Pseudo-code état client
struct ChunkState {
    sent_at: Timestamp,
    retry_count: u32,
    max_retries: u32,  // ex: 3
}

// Boucle de monitoring
if now - chunk.sent_at > TIMEOUT {
    if chunk.retry_count < chunk.max_retries {
        retransmit_chunk(chunk_index);
        chunk.retry_count += 1;
    } else {
        abort_transfer("Too many retries for chunk");
    }
}
```

**ACK négatif explicite :**
Si le serveur détecte un problème immédiatement (hash incorrect), il envoie un NACK :
```
DEFT CHUNK_ACK invoices-jan 42 ERROR HASH_MISMATCH
```
Le client retransmet immédiatement sans attendre le timeout.

### 11.5 Persistance et non-répudiation

**Stockage des accusés côté serveur :**
```
/var/deft/receipts/
  └── 2026/01/19/
      ├── transfer_uuid1234.json      # Métadonnées complètes
      ├── transfer_uuid1234.sig       # Signature cryptographique
      └── transfer_uuid1234.log       # Log détaillé chunk par chunk
```

**Signature cryptographique (optionnel mais recommandé) :**
- Le serveur signe l'accusé final avec sa clé privée
- Le client peut vérifier avec le certificat serveur
- Preuve d'authenticité et d'intégrité de l'accusé
- Utilisable en cas de litige ou audit

**Format de la preuve :**
```json
{
  "transfer_id": "550e8400-e29b-41d4-a716-446655440000",
  "protocol_version": "1.0",
  "virtual_file": "invoices-january-2026",
  "sender": {
    "partner_id": "acme-corp",
    "cert_fingerprint": "sha256:sender_cert..."
  },
  "receiver": {
    "partner_id": "supplier-inc",
    "cert_fingerprint": "sha256:receiver_cert..."
  },
  "transfer": {
    "start_time": "2026-01-19T14:30:00.000Z",
    "complete_time": "2026-01-19T14:35:23.456Z",
    "duration_seconds": 323.456,
    "chunk_size": 262144,
    "chunk_count": 400,
    "total_bytes": 104857600,
    "file_hash": "sha256:abc123def456...",
    "retransmissions": 3
  },
  "signature": {
    "algorithm": "RSA-SHA256",
    "value": "base64_encoded_signature...",
    "signer_cert": "sha256:receiver_cert..."
  }
}
```

### 11.6 Comparaison avec d'autres protocoles

| Protocole | ACK par chunk | ACK asynchrone | Fenêtre glissante | Preuve de livraison |
|-----------|---------------|----------------|-------------------|---------------------|
| FTP | Non | N/A | Non | Non |
| SFTP | Non | N/A | Non | Non |
| PESIT | Oui (sync) | Non | Non | Oui |
| AS2 | Non (fichier entier) | N/A | Non | Oui (MDN) |
| DEFT | Oui | Oui | Oui | Oui (signé) |

DEFT combine le meilleur des mondes : fiabilité granulaire de PESIT avec performance moderne de TCP et preuves cryptographiques d'AS2.

---

## 12. Spécifications techniques d'implémentation

Cette section documente les détails techniques de l'implémentation de référence.

### 12.1 Format des commandes protocolaires

Toutes les commandes commencent par `DEFT ` et se terminent par `\r\n`.

**Handshake :**
```
→ DEFT HELLO <version> <capabilities>
← DEFT WELCOME <version> <capabilities> WINDOW_SIZE:<n> <session_id>

Exemple :
→ DEFT HELLO 1.0 CHUNKED,PARALLEL,RESUME
← DEFT WELCOME 1.0 CHUNKED,PARALLEL,RESUME,COMPRESS WINDOW_SIZE:64 sess_1234567890_000
```

**Authentification :**
```
→ DEFT AUTH <partner_id>
← DEFT AUTH_OK "<partner_id>" VF:<virtual_files_list>

Exemple :
→ DEFT AUTH acme-corp
← DEFT AUTH_OK "acme-corp" VF:orders,invoices,catalog
```

**Découverte :**
```
→ DEFT DISCOVER
← DEFT FILES <count>
  <name> <size> <direction> <timestamp>
  ...
```

**Description d'un fichier virtuel :**
```
→ DEFT DESCRIBE <virtual_file>
← DEFT FILE_INFO <name> SIZE:<bytes> CHUNKS:<count> CHUNK_SIZE:<size> HASH:<sha256>
  CHUNK <index> SIZE:<size> HASH:<sha256>
  ...
```

**Transfert Push (envoi) :**
```
→ DEFT BEGIN_TRANSFER <virtual_file> <total_chunks> <total_bytes> <file_hash>
← DEFT TRANSFER_ACCEPTED <transfer_id> <virtual_file> WINDOW_SIZE:<n>

→ DEFT PUT <virtual_file> <chunk_index> <size> <hash>
← DEFT CHUNK_READY <virtual_file> <chunk_index> <size>
→ [binary chunk data]
← DEFT CHUNK_ACK <virtual_file> <chunk_index> OK

← DEFT TRANSFER_COMPLETE <virtual_file> <hash> <size> <chunks> sig:<signature>
```

**Transfert Pull (réception) :**
```
→ DEFT GET <virtual_file> CHUNKS <start>-<end>
← DEFT CHUNK_DATA <virtual_file> <chunk_index> SIZE:<size>
← [binary chunk data]
```

### 12.2 Architecture des modules Rust

```
deft/
├── deft-protocol/          # Définitions protocolaires (crate)
│   ├── command.rs          # Enum Command avec tous les types de commandes
│   ├── response.rs         # Enum Response avec tous les types de réponses
│   ├── parser.rs           # Parser bidirectionnel commandes ↔ texte
│   ├── capability.rs       # Négociation des capacités (CHUNKED, PARALLEL, etc.)
│   └── endpoint.rs         # Gestion multi-endpoints
│
├── deft-daemon/            # Daemon serveur + client
│   ├── main.rs             # Point d'entrée, CLI args, signal handling
│   ├── server.rs           # Accepte connexions TLS, dispatch vers handler
│   ├── handler.rs          # CommandHandler - traite chaque commande
│   ├── session.rs          # État de session (auth, permissions)
│   ├── config.rs           # Parsing config TOML
│   ├── virtual_file.rs     # VirtualFileManager - mapping VF ↔ filesystem
│   ├── transfer.rs         # TransferManager - suivi transferts actifs
│   ├── chunk_store.rs      # Stockage temporaire des chunks reçus
│   ├── api.rs              # API REST HTTP pour dashboard/monitoring
│   ├── hooks.rs            # Exécution scripts pre/post transfert
│   ├── signer.rs           # Signature Ed25519 des accusés
│   ├── receipt.rs          # Stockage des preuves de livraison
│   ├── metrics.rs          # Métriques Prometheus
│   └── rate_limit.rs       # Limitation connexions/bande passante
│
├── deft-cli/               # Client ligne de commande
│   └── main.rs             # Commandes: send, receive, history, status
│
└── deft-common/            # Utilitaires partagés
    ├── chunker.rs          # Découpage fichiers en chunks
    └── hash.rs             # Fonctions de hachage SHA-256
```

### 12.3 Flux de traitement serveur

```
1. TcpListener::accept()
2. TLS handshake (mTLS)
3. Création Session (non authentifiée)
4. Boucle lecture commandes :
   a. read_line() → texte commande
   b. Parser::parse_command() → Command enum
   c. handler.handle_command() → Response enum
   d. write response texte
   e. Si ChunkReady → lire binary data
   f. Si ChunkData → envoyer binary data
5. BYE ou timeout → fermeture session
```

### 12.4 État partagé (ApiState)

```rust
pub struct ApiState {
    pub config: RwLock<Config>,           // Config rechargeable à chaud
    pub start_time: Instant,              // Pour uptime
    pub transfers: RwLock<HashMap<String, TransferStatus>>,  // Transferts actifs
    pub history: RwLock<Vec<TransferHistoryEntry>>,          // Historique
    history_path: PathBuf,                // Persistance JSON
}
```

**Méthodes clés :**
- `register_transfer()` - Démarre le tracking d'un transfert
- `update_transfer_progress()` - Met à jour bytes/pourcentage
- `complete_transfer()` - Finalise et ajoute à l'historique
- `fail_transfer()` - Marque en erreur avec raison
- `save_history()` - Persiste dans `history.json`

### 12.5 API REST

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/status` | Uptime, version, connexions actives |
| GET | `/api/transfers` | Liste transferts en cours |
| GET | `/api/transfers/:id` | Détail d'un transfert |
| POST | `/api/transfers` | Démarrer un transfert |
| DELETE | `/api/transfers/:id` | Annuler un transfert |
| GET | `/api/history` | Historique des transferts |
| GET | `/api/partners` | Liste des partenaires configurés |
| GET | `/api/virtual-files` | Liste des fichiers virtuels |
| GET | `/api/config` | Configuration courante (sanitized) |

**Dashboard web** : Accessible sur `http://127.0.0.1:7742/`

### 12.6 Rechargement à chaud de la configuration

Le daemon supporte le rechargement de configuration sans redémarrage :

```bash
# Envoyer signal SIGHUP
kill -HUP $(pgrep deftd)
```

**Ce qui est rechargé :**
- Partenaires et leurs virtual files
- Paramètres de limites (rate limiting)
- Clé API

**Ce qui nécessite un redémarrage :**
- Changement de port d'écoute
- Changement de certificats TLS

### 12.7 Hooks d'événements

Scripts exécutables déclenchés sur événements :

```toml
[[hooks]]
event = "file-received"
command = "/usr/local/bin/process-invoice.sh"
partners = ["acme-corp"]
```

**Événements disponibles :**
- `pre-transfer` - Avant réception d'un fichier
- `post-transfer` - Après transfert complet
- `file-received` - Fichier assemblé avec succès
- `transfer-error` - Erreur pendant transfert

**Variables d'environnement passées :**
- `DEFT_TRANSFER_ID`
- `DEFT_VIRTUAL_FILE`
- `DEFT_PARTNER_ID`
- `DEFT_FILE_PATH` (si applicable)
- `DEFT_ERROR` (si erreur)

### 12.8 Signature des accusés de réception

Algorithme : **Ed25519**

```rust
pub struct ReceiptSigner {
    signing_key: SigningKey,  // Clé privée Ed25519
    verifying_key: VerifyingKey,
}
```

Format signature dans TRANSFER_COMPLETE :
```
sig:ed25519:<base64_signature>
```

La clé est générée au démarrage si non fournie. Pour la persistance, configurer :
```toml
[server]
signing_key = "/etc/deft/signing.key"
```

### 12.9 Métriques Prometheus

Disponibles sur `http://127.0.0.1:9090/metrics` :

| Métrique | Type | Description |
|----------|------|-------------|
| `deft_connections_total` | counter | Total connexions |
| `deft_connections_active` | gauge | Connexions actives |
| `deft_transfers_total{direction,status}` | counter | Transferts par direction/status |
| `deft_bytes_transferred_total{direction}` | counter | Bytes transférés |
| `deft_chunks_sent_total` | counter | Chunks envoyés |
| `deft_chunks_received_total` | counter | Chunks reçus |
| `deft_transfer_duration_seconds` | histogram | Durée des transferts |

### 12.10 Commandes CLI

```bash
# Envoyer un fichier (push)
deft --cert client.crt --key client.key --ca ca.crt \
    send <partner> <virtual_file> <file_path>

# Recevoir un fichier (pull)
deft --cert client.crt --key client.key --ca ca.crt \
    receive <partner> <virtual_file> <output_path>

# Voir l'historique des transferts
deft history --api http://127.0.0.1:7742 --limit 20

# Voir les transferts actifs
deft status --api http://127.0.0.1:7742

# Session interactive
deft --cert ... connect <partner>
```

---

## 13. Prochaines étapes

**Implémenté :**
- ✅ Handshake et authentification mTLS
- ✅ Transfert push avec chunks et validation hash
- ✅ Transfert pull avec DESCRIBE/GET
- ✅ API REST avec dashboard web
- ✅ Historique persistant des transferts
- ✅ Rechargement à chaud de la config (SIGHUP)
- ✅ Hooks d'événements
- ✅ Signature Ed25519 des accusés
- ✅ Métriques Prometheus

**À faire :**
- Delta sync (transfert incrémental)
- Compression des chunks (COMPRESS capability)
- Transfert parallèle multi-connexions
- Watchdir (surveillance répertoire auto-envoi)
- Interface web d'administration

---

*Document vivant - mis à jour le 20 Janvier 2026*