🛡️ Inventario de Seguridad - Gestión Integral 🚀
¡Bienvenido al sistema de gestión de inventario de seguridad más completo y fácil de usar! Este proyecto Full Stack te permite controlar tus roles, empleados, categorías, proveedores, productos, ubicaciones y movimientos de inventario de manera eficiente y segura.

✨ Características Destacadas
Autenticación Robusta:

🔐 Inicio de Sesión Local: Con bcrypt para contraseñas seguras.

🔑 Google OAuth 2.0: Inicia sesión con tu cuenta de Google en un clic.

🛡️ JSON Web Tokens (JWT): Para mantener tus sesiones seguras y escalables.

🤖 reCAPTCHA v2: Protege tus formularios de registro y login contra bots.

Gestión Completa de Entidades:

👥 Roles: Define y administra los permisos de acceso.

🧑‍💻 Empleados: Gestiona la información de tu personal.

🏷️ Categorías: Organiza tus productos de forma lógica.

🚚 Proveedores: Mantén un registro de tus suministradores.

📦 Productos: Detalla cada artículo de tu inventario.

📍 Ubicaciones: Controla dónde se encuentra cada producto.

📈 Movimientos de Inventario: Registra entradas y salidas para un seguimiento preciso.

Dashboard Interactivo: Visualiza métricas clave y el estado actual de tu inventario con gráficos intuitivos.

Interfaz de Usuario Moderna: Desarrollado con AdminLTE 3 y Bootstrap 4 para una experiencia de usuario responsive y agradable.

Tecnologías de Vanguardia: Construido con Node.js (Express) en el backend y MySQL2 como base de datos.

🛠️ Tecnologías Utilizadas
Backend:
Node.js 🟢

Express.js 🌐

MySQL2 🗄️

bcryptjs 🔒

jsonwebtoken (JWT) 🔑

express-session 🍪

passport & passport-google-oauth20 🛂

axios (para reCAPTCHA) 📡

dotenv (para gestión de variables de entorno) ⚙️

Frontend:
HTML5 📄

CSS3 🎨

JavaScript (ES6+) 🚀

jQuery ⚡

Bootstrap 4 💅

AdminLTE 3 📊

Chart.js (para gráficos del dashboard) 📈

Google reCAPTCHA v2 API 🤖

🚀 Cómo Empezar
Sigue estos pasos para poner en marcha el proyecto en tu máquina local.

1. Requisitos Previos
   Asegúrate de tener instalado lo siguiente:

Node.js (v14 o superior)

npm (viene con Node.js)

[enlace sospechoso eliminado] (v8.0 o superior)

2. Configuración de la Base de Datos
   Crea la base de datos MySQL:

Abre tu cliente MySQL (MySQL Workbench, línea de comandos, etc.).

Ejecuta el script SQL proporcionado en Inventario_seguridad.sql. Este script creará la base de datos inventario_seguridad (o inventario_seguridad_oauth si la has renombrado) y todas las tablas necesarias.

SQL

-- Ejemplo para ejecutar desde la línea de comandos (asegúrate de la ruta correcta del archivo):
mysql -u root -p < path/to/Inventario_seguridad.sql
¡Importante! Asegúrate de que el nombre de la base de datos en tu backend/server.js (database: 'inventario_seguridad_oauth' si lo cambiaste para OAuth) coincide con el nombre de la base de datos creada por el script (inventario_seguridad). Si no coinciden, edita uno de los dos para que lo hagan.

3. Configuración del Backend
   Navega a la carpeta backend:

Bash

cd tu_proyecto/backend
Instala las dependencias:

Bash

npm install
Configura las variables de entorno:

Crea un archivo .env en la raíz de la carpeta backend.

Añade las siguientes variables (reemplaza los valores con tus propias claves seguras y credenciales):

Fragmento de código

SESSION_SECRET='tu_secreto_de_sesion_largo_y_aleatorio_aqui'
JWT_SECRET='tu_clave_secreta_jwt_muy_larga_y_random_aqui'
GOOGLE_CLIENT_ID='tu_id_de_cliente_google_aqui'
GOOGLE_CLIENT_SECRET='tu_secreto_de_cliente_google_aqui'
GOOGLE_CALLBACK_URL='http://localhost:3000/auth/google/callback'
RECAPTCHA_SECRET_KEY='tu_clave_secreta_recaptcha_aqui'
¡Importante! Para GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET, debes crear credenciales OAuth 2.0 en la Consola de Desarrolladores de Google Cloud. Asegúrate de añadir http://localhost:3000/auth/google/callback como un URI de redirección autorizado para tu aplicación web.

¡Importante! Para RECAPTCHA_SECRET_KEY, obtén tu clave secreta de Google reCAPTCHA. Utiliza reCAPTCHA v2 (checkbox) para este proyecto.

Inicia el servidor backend:

Bash

npm start
El servidor se ejecutará en http://localhost:3000.

4. Acceso al Frontend
   El frontend ya está configurado para ser servido por el servidor Express.

Abre tu navegador:

Ve a http://localhost:3000.

Deberías ver la página de inicio de sesión (login.html).

👨‍💻 Uso del Sistema
Registro:

Si no tienes una cuenta, regístrate utilizando el formulario o la opción de Google.

Asegúrate de que reCAPTCHA funcione correctamente.

Inicio de Sesión:

Inicia sesión con tu cuenta local o a través de Google.

Navegación:

Una vez autenticado, serás redirigido al Dashboard.

Usa el menú lateral para navegar entre las diferentes secciones (Empleados, Productos, etc.).

Gestión de Datos:

En cada sección, puedes listar, añadir, editar y eliminar registros.

🤝 Contribuciones
¡Las contribuciones son bienvenidas! Si tienes ideas para mejorar el proyecto, no dudes en:

Forkear el repositorio.

Crear una nueva rama (git checkout -b feature/nueva-caracteristica).

Realizar tus cambios y hacer commit (git commit -m 'feat: Añadir nueva característica X').

Subir tus cambios (git push origin feature/nueva-caracteristica).

Abrir un Pull Request.

📄 Licencia
Este proyecto está bajo la licencia ISC License.

¡Disfruta gestionando tu inventario de seguridad! 🎉