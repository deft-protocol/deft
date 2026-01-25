# DEFT - Kanban des Tâches

**Dernière mise à jour** : 26 Janvier 2026  
**Version actuelle** : v2.3.3

---

## 🔴 CRITIQUE (Qualité)

| ID | Tâche | Effort | Status | Assigné | Notes |
|----|-------|--------|--------|---------|-------|
| C1 | Tests automatisés delta-sync | 1j | ⏳ TODO | - | Tests d'intégration: fichier modifié, nouveau fichier, gros fichier |
| C2 | Tests automatisés pause/resume | 1j | ⏳ TODO | - | Tests cross-party: pause sender → resume receiver |

---

## 🟠 HAUTE (Documentation & Sécurité)

| ID | Tâche | Effort | Status | Assigné | Notes |
|----|-------|--------|--------|---------|-------|
| H1 | Documentation API OpenAPI/Swagger | 1j | ⏳ TODO | - | Spec OpenAPI 3.0 pour tous les endpoints REST |
| H2 | Mettre à jour AUDIT.md | 0.5j | ⏳ TODO | - | Ajouter section API Key authentication |
| H3 | Tests sécurité API Key | 0.5j | ⏳ TODO | - | Tests rotation, rejection, localhost-only |

---

## 🟡 MOYENNE (Fonctionnalités v2.0)

| ID | Tâche | Effort | Status | Assigné | Notes |
|----|-------|--------|--------|---------|-------|
| M1 | Transfert parallèle multi-connexions | 3j | ⏳ TODO | - | Activer `parallel.rs` pour agrégation bande passante |
| M2 | Gestion priorités transferts | 2j | ⏳ TODO | - | Queue avec priorités (urgent/normal/batch) |
| M3 | Amélioration UI dashboard | 1j | ⏳ TODO | - | Affichage API Key, bouton rotation |

---

## 🟢 BASSE (Écosystème v3.0)

| ID | Tâche | Effort | Status | Assigné | Notes |
|----|-------|--------|--------|---------|-------|
| L1 | SDK Python | 3j | ⏳ TODO | - | Client Python avec async/await |
| L2 | SDK JavaScript | 3j | ⏳ TODO | - | Client Node.js/Deno |
| L3 | Clustering/HA | 5j | ⏳ TODO | - | Redis/etcd pour état partagé |
| L4 | Chiffrement E2E au repos | 3j | ⏳ TODO | - | Chiffrement fichiers stockés |

---

## ✅ TERMINÉ (Récent)

| ID | Tâche | Date | Notes |
|----|-------|------|-------|
| ~~D1~~ | Sécurisation API REST | 26/01/2026 | API Key auto-générée, rotation, constant-time comparison |
| ~~D2~~ | Fix delta-sync directories | 25/01/2026 | `find_most_recent_file()` pour virtual files = répertoires |
| ~~D3~~ | Fix pause/resume cross-party | 25/01/2026 | Consommation réponses TRANSFER_PAUSED périmées |
| ~~D4~~ | Fix UI progress updates | 25/01/2026 | `updateTransferProgress` pour layout cards |

---

## 📊 Résumé

| Priorité | Total | TODO | En cours | Terminé |
|----------|-------|------|----------|---------|
| 🔴 Critique | 2 | 2 | 0 | 0 |
| 🟠 Haute | 3 | 3 | 0 | 0 |
| 🟡 Moyenne | 3 | 3 | 0 | 0 |
| 🟢 Basse | 4 | 4 | 0 | 0 |
| **Total** | **12** | **12** | **0** | **4** |

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
