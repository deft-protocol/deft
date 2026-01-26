# DEFT - Kanban des Tâches

**Dernière mise à jour** : 26 Janvier 2026  
**Version actuelle** : v2.3.3

---

## 🔴 CRITIQUE (Qualité)

| ID | Tâche | Effort | Status | Assigné | Notes |
|----|-------|--------|--------|---------|-------|
| C1 | Tests automatisés delta-sync | 1j | ✅ DONE | - | 4 tests: new file, small mod, large mod, integrity |
| C2 | Tests automatisés pause/resume | 1j | ✅ DONE | - | 4 tests: same-party, cross-party, multi-cycle, long pause |

---

## 🟠 HAUTE (Documentation & Sécurité)

| ID | Tâche | Effort | Status | Assigné | Notes |
|----|-------|--------|--------|---------|-------|
| H1 | Documentation API OpenAPI/Swagger | 1j | ✅ DONE | - | `docs/openapi.yaml` - 800+ lignes |
| H2 | Mettre à jour AUDIT.md | 0.5j | ✅ DONE | - | Section 2.1.1 API Key Authentication ajoutée |
| H3 | Tests sécurité API Key | 0.5j | ✅ DONE | - | 8 tests: rotation, rejection, permissions |

---

## 🟡 MOYENNE (Fonctionnalités v2.0)

| ID | Tâche | Effort | Status | Assigné | Notes |
|----|-------|--------|--------|---------|-------|
| M1 | Transfert parallèle multi-connexions | 3j | ✅ DONE | - | Config `max_parallel_streams`, `parallel.rs` intégré |
| M2 | Gestion priorités transferts | 2j | ✅ DONE | - | `priority.rs` - queue urgent/normal/batch |
| M3 | Amélioration UI dashboard | 1j | ✅ DONE | - | Fix accès sans auth, API Key auto-fetch |

---

## 🟢 BASSE (Écosystème v3.0)

| ID | Tâche | Effort | Status | Assigné | Notes |
|----|-------|--------|--------|---------|-------|
| L1 | SDK Python | 3j | ✅ DONE | - | `sdk/python/` - async client + sync wrapper |
| L2 | SDK JavaScript | 3j | ✅ DONE | - | `sdk/javascript/` - TypeScript client |
| L3 | Clustering/HA | 5j | ✅ DONE | - | `cluster.rs` - node discovery, heartbeat, state sync |
| L4 | Chiffrement E2E au repos | 3j | ✅ DONE | - | `encryption.rs` - AES-256-GCM + key rotation |

---

## ✅ TERMINÉ (Récent)

| ID | Tâche | Date | Notes |
|----|-------|------|-------|
| ~~M1~~ | Transfert parallèle | 26/01/2026 | Config `max_parallel_streams` |
| ~~M2~~ | Priorités transferts | 26/01/2026 | `priority.rs` - queue triée |
| ~~L1~~ | SDK Python | 26/01/2026 | `sdk/python/` - async + sync |
| ~~L2~~ | SDK JavaScript | 26/01/2026 | `sdk/javascript/` - TypeScript |
| ~~L3~~ | Clustering/HA | 26/01/2026 | `cluster.rs` - nodes, heartbeat |
| ~~L4~~ | Chiffrement E2E | 26/01/2026 | `encryption.rs` - AES-256-GCM |
| ~~H1~~ | Documentation OpenAPI | 26/01/2026 | `docs/openapi.yaml` - spec complète |
| ~~H2~~ | Update AUDIT.md | 26/01/2026 | Section API Key Authentication |
| ~~H3~~ | Tests sécurité API Key | 26/01/2026 | `api_key_security_test.rs` - 8 tests |
| ~~M3~~ | Fix dashboard auth | 26/01/2026 | Static files exemptés de l'auth |
| ~~C1~~ | Tests automatisés delta-sync | 26/01/2026 | `delta_sync_integration.rs` - 4 tests |
| ~~C2~~ | Tests automatisés pause/resume | 26/01/2026 | `pause_resume_full_integration.rs` - 4 tests |
| ~~D1~~ | Sécurisation API REST | 26/01/2026 | API Key auto-générée, rotation |
| ~~D2~~ | Fix delta-sync directories | 25/01/2026 | `find_most_recent_file()` |
| ~~D3~~ | Fix pause/resume cross-party | 25/01/2026 | Consommation réponses périmées |
| ~~D4~~ | Fix UI progress updates | 25/01/2026 | `updateTransferProgress` |

---

## 📊 Résumé

| Priorité | Total | TODO | Backlog | Terminé |
|----------|-------|------|---------|---------|
| 🔴 Critique | 2 | 0 | 0 | 2 |
| 🟠 Haute | 3 | 0 | 0 | 3 |
| 🟡 Moyenne | 3 | 0 | 0 | 3 |
| 🟢 Basse | 4 | 0 | 0 | 4 |
| **Total** | **12** | **0** | **0** | **12** |

---

## Légende Status

- ⏳ TODO : À faire
- 🔄 IN PROGRESS : En cours
- ✅ DONE : Terminé
- ❌ BLOCKED : Bloqué
- 🔙 BACKLOG : Reporté

---

## Notes de Version

### v2.3.3 (26/01/2026)
- ✅ API Key authentication pour REST API
- ✅ Fix delta-sync pour répertoires de réception
- ✅ Fix pause/resume synchronisation

### v2.3.2 (25/01/2026)
- ✅ Fix UI progress bar après resume
- ✅ Fix false "failed to resume" message
