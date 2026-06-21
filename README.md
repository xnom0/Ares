Ares est un outil en ligne de commande (CLI) écrit en Go qui permet de créer et extraire des archives sécurisées et compressées avec un très haut niveau de sécurité.

Il combine trois étapes puissantes dans un seul flux :

- TAR → Empaquetage des fichiers/dossiers (préservation de la structure et des permissions)
- LZMA2 (via ulikunitz/xz) → Compression très efficace
- Chiffrement hybride moderne (X25519 + AES-256-GCM) → Chiffrement fort avec confidentialité persistante (forward secrecy)

Le format de fichier résultant est .ares.

## Compilation depuis GNU/Linux pour GNU/Linux : 

`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ares`

## Compilation depuis GNU/Linux pour Windows : 

`CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ares.exe`

## Utilisation :

`ares generate : Permet de crée une pair de clé 
ares compress fichier_original.ext fichier_compresser [0-9]`
`ares decompress fichier_compresser.ares fichier_original.ext`

par defaut la clé privé et publique doivent etre dans le meme dossier que l'outil sinon il faut spécifier l'emplacement de la clé :

`ares compress fichier_original.ext fichier_compresser [0-9] /opt/mykey.pub
ares decompress fichier_compresser.ares fichier_original.ext /opt/mykey.priv`
