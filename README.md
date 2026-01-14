# SecureChat – Messagerie Sécurisée en Java

*Réalisé par* : Yosra BOURRAT et Fatima Zahra NACIRI

*Encadré par* : M.BENTAJER

## Description

SecureChat est une application Client–Serveur sécurisée en Java permettant à plusieurs utilisateurs d’échanger des messages chiffrés via des sockets TCP.
Le projet met en pratique la programmation orientée objet, la communication réseau et l’utilisation d’API de cryptographie (AES & RSA).

---

## Objectifs demandés dans l’exercice

* Développer un modèle **Client / Serveur** basé sur les sockets.
* Gérer plusieurs clients simultanément via des **threads**.
* **Chiffrer et déchiffrer** tous les messages échangés.
* Implémenter une architecture orientée objet propre (Client, Serveur, Sécurité…).
* Assurer une **déconnexion propre** d’un client.
* (Optionnel) Journaliser les messages chiffrés.

---

## Fonctionnalités réalisées

### - Connexion au serveur

* Le client saisit l’adresse IP et le port.
* Le serveur accepte plusieurs clients en parallèle.
* Chaque utilisateur choisit un **pseudonyme** unique.

### - Envoi et réception de messages

* Le client envoie un message.
* Le serveur le redistribue à tous les clients connectés.
* Le message diffusé contient : **pseudo + texte chiffré**.

### - Sécurisation complète

* Les messages sont **chiffrés en AES** côté client avant l’envoi.
* Le serveur déchiffre et redistribue les messages chiffrés.
* La **clé secrète AES** est transmise via un échange **RSA**.

### - Déconnexion propre

* Le client peut quitter simplement en tapant :
  **Bye** ou **Goodbye**
* Un message chiffré final est envoyé avant la fermeture.
* Le message local affiché est : **“You quit conversation”**.

---

## Structure du projet

```
src/
 ├── SecureChatServer.java
 ├── SecureChatClient.java
 ├── ClientHandler.java
 └── CryptoUtils.java
```

---

## Auteur

Projet réalisé dans un cadre pédagogique sur les communications sécurisées en Java.
