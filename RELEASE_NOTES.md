# Kernel-AV v0.1.0

Première version expérimentale de Kernel-AV pour Windows.

## Fonctionnalités

- analyse à la demande avec SHA-256, signatures SQLite et règles YARA ;
- heuristiques pour scripts, PowerShell, macros Office et exécutables suspects ;
- surveillance en temps réel des fichiers ;
- télémétrie et heuristiques sur les nouveaux processus ;
- détection non destructive d'activités de type ransomware ;
- quarantaine vérifiée par empreinte et restauration sans écrasement ;
- journalisation structurée des détections et alertes comportementales.

## Téléchargement

- `Kernel-AV.exe` : exécutable Windows autonome avec les règles YARA embarquées ;
- `SHA256SUMS.txt` : empreinte SHA-256 de l'exécutable.

## Avertissement

Cette version est expérimentale, non signée et ne remplace pas Microsoft Defender ou un EDR de
production. Windows SmartScreen peut afficher un avertissement, faute de certificat de signature
de code. La réponse anti-ransomware est uniquement informative : aucun processus n'est arrêté
automatiquement et aucun fichier n'est supprimé.

