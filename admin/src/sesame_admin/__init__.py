# SPDX-License-Identifier: Apache-2.0
"""Interface web d'administration Sesame.

Gestion du registre des comptes et des identifiants applicatifs : un
administrateur définit le compte applicatif d'un utilisateur (écrit dans le
coffre, sans pouvoir le relire) et l'entrée correspondante du registre, dans la
même opération. Les descripteurs d'applis restent des fichiers versionnés,
affichés en lecture seule. Accès réservé à un groupe d'administrateurs ; chaque
action est tracée dans l'audit.
"""
