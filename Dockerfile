# Usa imagen oficial de Node.js
FROM node:20

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar archivos de dependencias
COPY package*.json ./

# Instalar dependencias
RUN npm install

# Copiar el resto del código
COPY . .

# Expone el puerto que usa la app
EXPOSE 3000

# Comando para iniciar la app
CMD ["npm", "start"]
