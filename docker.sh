#!/bin/bash

# Nom de l'image Docker (tu peux personnaliser ce nom)
IMAGE_NAME="debian_test"
CONTAINER_NAME="famine"
DOCKERFILE="Dockerfile"

# Vérifier si un conteneur avec ce nom existe déjà et le supprimer s'il est présent
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Un conteneur avec le nom $CONTAINER_NAME existe déjà. Suppression..."
    docker rm -f "$CONTAINER_NAME"
fi

# Vérifier si l'image existe
if docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    # Récupérer la date de création de l'image
    IMAGE_CREATED=$(docker image inspect "$IMAGE_NAME" --format '{{.Created}}' | xargs -I{} date -d {} +%s)
    # Récupérer la date de modification du Dockerfile
    FILE_MODIFIED=$(date -r "$DOCKERFILE" +%s)

    if [ "$FILE_MODIFIED" -gt "$IMAGE_CREATED" ]; then
        echo "Le Dockerfile a été modifié. Reconstruction de l'image..."
        docker rmi -f "$IMAGE_NAME"
        docker build -t "$IMAGE_NAME" .
    else
        echo "L'image est à jour. Pas besoin de rebuild."
    fi
else
    echo "L'image $IMAGE_NAME n'existe pas encore. Construction..."
    docker build -t "$IMAGE_NAME" .
fi

# Vérifier si la construction a réussi
if [ $? -ne 0 ]; then
    echo "Erreur lors de la construction de l'image."
    exit 1
fi

# Lancer un conteneur à partir de l'image construite
echo "Lancement du conteneur à partir de l'image $IMAGE_NAME avec le nom $CONTAINER_NAME"
docker run --rm -it --name "$CONTAINER_NAME" -v "$(pwd)":/root/famine "$IMAGE_NAME"

# Vérifier si le conteneur a démarré correctement
if [ $? -eq 0 ]; then
    echo "Le conteneur a démarré avec succès."
else
    echo "Erreur lors du démarrage du conteneur."
    exit 1
fi
