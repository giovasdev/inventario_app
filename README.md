# 🛡️ Inventario de Seguridad – Gestión Full Stack 🚀  
[![Node.js](https://img.shields.io/badge/Node.js-v14%2B-green)](https://nodejs.org/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0%2B-blue)](https://www.mysql.com/)
[![License: ISC](https://img.shields.io/badge/License-ISC-lightgrey.svg)](https://opensource.org/licenses/ISC)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-4-blueviolet)](https://getbootstrap.com/)
[![reCAPTCHA](https://img.shields.io/badge/reCAPTCHA-v2-important)](https://www.google.com/recaptcha/)

¡Bienvenido al sistema más **seguro**, **moderno** y **fácil de usar** para administrar tu inventario de seguridad!

---

## ✨ Funcionalidades Clave

🔐 **Autenticación Segura**  
- Login local con `bcrypt`  
- Inicio de sesión con Google (OAuth 2.0)  
- JWT para sesiones seguras  
- Protección anti-bots con reCAPTCHA v2  

📦 **Gestión de Entidades**  
- 👤 Roles & Empleados  
- 🏷️ Categorías  
- 🚚 Proveedores  
- 📦 Productos  
- 📍 Ubicaciones  
- 🔁 Movimientos de Inventario  

📊 **Dashboard Interactivo**  
Visualiza métricas clave con **Chart.js**  

💻 **UI Moderna y Responsive**  
Diseñada con **AdminLTE 3** + **Bootstrap 4**

---

## 🛠️ Stack Tecnológico

**🔧 Backend:**  
- Node.js + Express  
- MySQL2  
- JWT + bcryptjs  
- Passport (OAuth2)  
- reCAPTCHA API v2  
- dotenv  

**🎨 Frontend:**  
- HTML5 + CSS3  
- JavaScript (ES6+)  
- jQuery  
- Bootstrap 4  
- AdminLTE 3  
- Chart.js  

---

## 🚀 Guía Rápida de Instalación

### 1️⃣ Pre-requisitos  
- Node.js `v14+`  
- npm (viene con Node.js)  
- MySQL `v8+`  

### 2️⃣ Configura la Base de Datos  
Ejecuta el archivo SQL incluido:  
```bash
mysql -u root -p < path/to/Inventario_seguridad.sql
```

> Asegúrate de que el nombre de la base de datos coincida con el archivo `.env` → `inventario_seguridad` o `inventario_seguridad_oauth`.

### 3️⃣ Configura el Backend
```bash
cd backend
npm install
```

Crea un archivo `.env` y agrega:
```env
SESSION_SECRET=tu_clave_de_sesion
JWT_SECRET=tu_clave_jwt
GOOGLE_CLIENT_ID=tu_id_google
GOOGLE_CLIENT_SECRET=tu_secreto_google
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback
RECAPTCHA_SECRET_KEY=tu_clave_recaptcha
```

> 🔐 Crea tus credenciales de OAuth2 y reCAPTCHA en Google Cloud Console.

Inicia el servidor:
```bash
npm start
```

### 4️⃣ Accede al sistema  
Abre tu navegador en:  
👉 http://localhost:3000

---

## 👨‍💻 ¿Cómo usarlo?

- **Registrarse o Iniciar sesión** con cuenta local o Google  
- **Validación** con reCAPTCHA  
- Accede al **Dashboard**  
- Navega por módulos: empleados, productos, ubicaciones, etc.  
- Crea, edita o elimina registros fácilmente  

---

## 🤝 Contribuciones

¡Nos encanta recibir ideas nuevas!  
1. Haz un `fork`  
2. Crea una rama:  
   ```bash
   git checkout -b feature/tu-mejora
   ```
3. Realiza tus cambios y haz commit  
4. Envía un Pull Request 🚀  

---

## 📄 Licencia

Distribuido bajo la licencia **ISC**.  
[Ver licencia](https://opensource.org/licenses/ISC)

---

> ¡Gestiona tu inventario como un profesional!  
> **Seguro. Escalable. Eficiente.** 😎📦
