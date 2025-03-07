#!/bin/bash

# Nom de l'image Docker (tu peux personnaliser ce nom)
IMAGE_NAME="debian_test"
CONTAINER_NAME="famine"

# Vérifier si l'image existe déjà et la supprimer
if docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    echo "L'image $IMAGE_NAME existe déjà. Suppression de l'image..."
    docker rmi -f "$IMAGE_NAME"
else
    echo "L'image $IMAGE_NAME n'existe pas encore."
fi

# Construire l'image Docker
echo "Construction de l'image Docker : $IMAGE_NAME"
docker build -t "$IMAGE_NAME" .

# Vérifier si la construction a réussi
if [ $? -eq 0 ]; then
    echo "L'image a été construite avec succès !"
else
    echo "Erreur lors de la construction de l'image."
    exit 1
fi

# Lancer un conteneur à partir de l'image construite
echo "Lancement du conteneur à partir de l'image $IMAGE_NAME avec le nom $CONTAINER_NAME"
docker run -it --name "$CONTAINER_NAME" "$IMAGE_NAME"

# Vérifier si le conteneur a démarré correctement
if [ $? -eq 0 ]; then
    echo "Le conteneur a démarré avec succès."
else
    echo "Erreur lors du démarrage du conteneur."
    exit 1
fi
