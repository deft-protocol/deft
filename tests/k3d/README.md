# DEFT Parallel Transfer Tests with k3d

Tests de transferts parallèles multi-nœuds utilisant k3d (Kubernetes in Docker).

## Prérequis

- Docker
- k3d (`curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash`)
- kubectl
- openssl

## Structure

```
tests/k3d/
├── Dockerfile              # Image Docker DEFT
├── deft-cluster.yaml       # Config cluster k3d
├── run-parallel-tests.sh   # Script de tests
├── manifests/
│   ├── namespace.yaml      # Namespace Kubernetes
│   └── deft-node.yaml      # StatefulSet DEFT (3 réplicas)
└── README.md
```

## Exécution

```bash
# Lancer tous les tests
./tests/k3d/run-parallel-tests.sh
```

Le script va automatiquement :
1. Construire l'image Docker DEFT
2. Créer un cluster k3d avec 3 agents (simulant 3 interfaces réseau)
3. Générer les certificats mTLS
4. Déployer 3 nœuds DEFT
5. Exécuter les tests de transfert parallèle

## Tests exécutés

| Test | Description |
|------|-------------|
| Single stream | Transfert 100MB sur une seule connexion |
| Parallel 4x | 4 transferts simultanés depuis le même nœud |
| Multi-node | Transferts simultanés depuis tous les nœuds |

## Résultats attendus

Les transferts parallèles et multi-nœuds devraient montrer une amélioration
significative du débit par rapport au transfert single-stream, démontrant
l'efficacité de l'agrégation de bande passante.

## Nettoyage

Le cluster k3d est automatiquement supprimé à la fin des tests.
Pour nettoyer manuellement :

```bash
k3d cluster delete deft-test
```
