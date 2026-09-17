# Kernel-AV v0.2.0 — service Windows natif

Cette version amorce la migration progressive hors de Python.

## Nouveau

- installateur MSI Windows x64 ;
- service Windows `.NET 8` autonome, sans Python ;
- démarrage automatique et désinstallation propre du service ;
- surveillance native des créations, modifications et déplacements de fichiers ;
- SHA-256 et heuristiques PowerShell natives ;
- détection native, non destructive, des rafales d'activité de type ransomware ;
- journal JSON Lines dans `%ProgramData%\Kernel-AV\events.jsonl`.

## Migration progressive

Le moteur Python historique reste dans le dépôt pendant que les fonctions plus avancées sont
migrées et comparées. L'installateur `v0.2.0` n'installe pas Python et le service natif ne lance
aucun interpréteur Python.

## Limites

Cette version reste expérimentale et non signée. Elle ne remplace pas Microsoft Defender ou un
EDR de production. Le service signale les activités suspectes mais ne tue aucun processus et ne
supprime aucun fichier automatiquement.

