const express = require("express");
const { v5: uuidv5 } = require("uuid");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { google } = require("googleapis");
const admin = require("firebase-admin");
const axios = require("axios");

const serviceAccount = require("./firebase-admin.json");

// Configuración de la conexión a la base de datos
const pool = new Pool({
  user: "postgres",
  password: "1235",
  host: "localhost",
  port: 5432,
  database: "db",
});

const MESSAGING_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const SCOPES = [MESSAGING_SCOPE];

const app = express();
const port = 3000;
const secretKey = "shadow"; // Clave secreta para firmar JWT
const namespace = uuidv5(secretKey, uuidv5.DNS); // Genera un UUID v5 basado en la palabra secretKey
const saltRounds = 10; // Número de rondas para el hashing de la contraseña

// Middleware para analizar el cuerpo de las solicitudes como JSON
app.use(express.json());

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

async function getAccessToken() {
  return new Promise(function (resolve, reject) {
    const key = require("./firebase-admin.json");
    const jwtClient = new google.auth.JWT(
      key.client_email,
      null,
      key.private_key,
      SCOPES,
      null
    );
    jwtClient.authorize(function (err, tokens) {
      if (err) {
        reject(err);
        return;
      }
      resolve(tokens.access_token);
    });
  });
}

// Middleware para verificar el token de acceso en las solicitudes protegidas
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

app.post("/api/message:send", async (req, res) => {
  try {
    const { userId, title, body, data, image } = req.body;

    const message = "";

    const notificationData = {
      title: title,
      body: body,
      user_id: userId,
      image_url: image || null,
      data: data || null,
    };

    const client = await pool.connect();

    await client.query(
      "INSERT INTO notifications (title, body, user_id, image_url, data) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [
        notificationData.title,
        notificationData.body,
        notificationData.user_id,
        notificationData.image_url,
        notificationData.data,
      ]
    );

    // Obtener todos los tokens de dispositivos para el user_id
    const devices = await client.query(
      "SELECT device_token FROM devices WHERE user_id = $1",
      [userId]
    );

    client.release();

    const token = await getAccessToken();
    // console.log(token);

    const FMCHeaders = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    };

    const url =
      "https://fcm.googleapis.com/v1/projects/push-app-notifications-cac04/messages:send";

    const devices_token = devices.rows.map((row) => row.device_token);

    let responses = [];

    for (let device_token of devices_token) {
      const FCMData = {
        message: {
          token: device_token,
          data: data || null,
          notification: {
            title: title,
            body: body,
            image: image || null,
          },
        },
      };

      try {
        const response = await axios.post(url, FCMData, {
          headers: FMCHeaders,
          validateStatus: function (status) {
            // Resolver la promesa para todos los códigos de estado
            return true; // Siempre considerar las respuestas como exitosas
          },
        });

        if (response.status === 404) {
          await axios.delete("http://localhost:3000/api/deleteDevice", {
            data: {
              device_token: device_token,
              user_id: userId,
            },
          });
          message = "Token ${device_token} eliminado";
        }

        responses.push({
          token: device_token,
          status: response.status,
          data: response.data,
          message: message || "Notificación enviada y guardada",
        });
      } catch (axiosError) {
        responses.push({
          token: device_token,
          status: 500,
          message: "Internal error during FCM request",
          error: axiosError.message,
        });
      }
    }

    res.status(200).json({
      status: 200,
      responses: responses,
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: "Internal server error",
      error: error.message,
    });
  }
});

// Endpoint para registro de usuarios de facebook
app.post("/api/registerFacebook", async (req, res) => {
  const { access_token } = req.body;
  // Solicitar información del usuario a Facebook
  const userInfoResponse = await axios.get(
    `https://graph.facebook.com/me?access_token=${access_token}&fields=id,name,email`
  );
  const userInfo = userInfoResponse.data;

  const username = userInfo.email;

  try {
    // Verificar si el nombre de usuario ya existe
    const client = await pool.connect();
    const usernameExists = await client.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (usernameExists.rows.length > 0) {
      client.release();
      return res
        .status(400)
        .json({ status: 400, message: "El correo ya está en uso" });
    }

    const account_type = "facebook";

    // Insertar el nuevo usuario en la base de datos
    await client.query(
      "INSERT INTO users (username, password, account_type) VALUES ($1, $2, $3) RETURNING *",
      [username, null, account_type]
    );
    client.release();

    res
      .status(201)
      .json({ status: 201, message: "Usuario registrado exitosamente" });
  } catch (err) {
    console.error("Error al registrar usuario", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Endpoint para registro de usuarios de google
app.post("/api/registerGoogle", async (req, res) => {
  const { id_token } = req.body;

  const decodedHeader = jwt.decode(id_token, { complete: true });

  console.log(decodedHeader);

  if (decodedHeader.payload.email_verified === false) {
    return res
      .status(401)
      .json({ status: 401, message: "El correo no es un correo verificado" });
  }

  const username = decodedHeader.payload.email;

  try {
    // Verificar si el nombre de usuario ya existe
    const client = await pool.connect();
    const usernameExists = await client.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (usernameExists.rows.length > 0) {
      client.release();
      return res
        .status(400)
        .json({ status: 400, message: "El correo ya está en uso" });
    }

    const account_type = "google";

    // Insertar el nuevo usuario en la base de datos
    await client.query(
      "INSERT INTO users (username, password, account_type) VALUES ($1, $2, $3) RETURNING *",
      [username, null, account_type]
    );
    client.release();

    res
      .status(201)
      .json({ status: 201, message: "Usuario registrado exitosamente" });
  } catch (err) {
    console.error("Error al registrar usuario", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Endpoint para registro de usuarios
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Verificar si el nombre de usuario ya existe
    const client = await pool.connect();
    const usernameExists = await client.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (usernameExists.rows.length > 0) {
      client.release();
      return res
        .status(400)
        .json({ status: 400, message: "El nombre de usuario ya está en uso" });
    }

    // Hash de la contraseña
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const account_type = "app";

    // Insertar el nuevo usuario en la base de datos
    await client.query(
      "INSERT INTO users (username, password, account_type) VALUES ($1, $2, $3) RETURNING *",
      [username, hashedPassword, account_type]
    );
    client.release();

    res
      .status(201)
      .json({ status: 201, message: "Usuario registrado exitosamente" });
  } catch (err) {
    console.error("Error al registrar usuario", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Endpoint para iniciar sesión a travez de facebook y obtener token de acceso
app.post("/api/loginFacebook", async (req, res) => {
  const { access_token } = req.body;
  // Solicitar información del usuario a Facebook
  const userInfoResponse = await axios.get(
    `https://graph.facebook.com/me?access_token=${access_token}&fields=id,name,email`
  );
  const userInfo = userInfoResponse.data;

  const username = userInfo.email;

  try {
    const client = await pool.connect();
    const result = await client.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    const user = result.rows[0];

    if (!user) {
      res.status(401).json({ status: 401, message: "Usuario no encontrado" });
      return;
    }

    const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: "1h" }); // Firmar token con el ID del usuario
    client.release();
    res
      .status(200)
      .json({ status: 200, message: "Inicio de sesión exitosa", token: token });
  } catch (err) {
    console.error("Error al iniciar sesión", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Endpoint para iniciar sesión a travez de google y obtener token de acceso
app.post("/api/loginGoogle", async (req, res) => {
  const { id_token } = req.body;

  const decodedHeader = jwt.decode(id_token, { complete: true });

  console.log(decodedHeader.payload.sub);

  const username = decodedHeader.payload.email;

  try {
    const client = await pool.connect();
    const result = await client.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    const user = result.rows[0];

    if (!user) {
      res.status(401).json({ status: 401, message: "Usuario no encontrado" });
      return;
    }

    const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: "1h" }); // Firmar token con el ID del usuario
    client.release();
    res
      .status(200)
      .json({ status: 200, message: "Inicio de sesión exitosa", token: token });
  } catch (err) {
    console.error("Error al iniciar sesión", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Endpoint para iniciar sesión a travez de la app y obtener token de acceso
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const client = await pool.connect();
    const result = await client.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    client.release();

    const user = result.rows[0];

    if (!user) {
      res.status(401).json({ status: 401, message: "Usuario no encontrado" });
      return;
    }
    if (user.account_type === "app") {
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        res.status(401).json({ status: 401, message: "Contraseña incorrecta" });
        return;
      }

      const token = jwt.sign({ userId: user.id }, secretKey, {
        expiresIn: "1h",
      }); // Firmar token con el ID del usuario
      res.status(200).json({
        status: 200,
        message: "Inicio de sesión exitosa",
        token: token,
      });
    } else {
      res.status(404).json({ status: 404, message: "Usuario no válido" });
    }
  } catch (err) {
    console.error("Error al iniciar sesión", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Endpoint para iniciar sesión con huella digital
app.post("/api/loginWithFingerprint", async (req, res) => {
  const { username, device_info_token } = req.body;

  if (!device_info_token) {
    return res.status(400).json({
      status: 400,
      message: "Falta el token de información del dispositivo",
    });
  }

  const fingerprintToken = uuidv5(device_info_token, namespace);

  try {
    const client = await pool.connect();

    // Verificar si el usuario existe y tiene la huella digital habilitada
    const result = await client.query(
      "SELECT id, username, fingerprint_token FROM users WHERE username = $1 AND fingerprint_token = $2",
      [username, fingerprintToken]
    );

    const user = result.rows[0];

    if (!user) {
      client.release();
      return res
        .status(401)
        .json({ status: 401, message: "Usuario no encontrado" });
    }

    if (!user.fingerprint_token) {
      client.release();
      return res.status(403).json({
        status: 403,
        message: "La huella digital no está habilitada para este usuario",
      });
    }

    // Generar un token JWT para el usuario
    const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: "1h" });

    client.release();

    // Devolver el token de acceso
    res.status(200).json({
      status: 200,
      message: "Inicio de sesión exitoso con huella digital",
      token: token,
    });
  } catch (err) {
    console.error("Error al iniciar sesión con huella digital", err);
    res.status(500).json({
      status: 500,
      message:
        "Error interno del servidor al iniciar sesión con huella digital",
    });
  }
});

// Endpoint para obtener la información del usuario conectado
app.get("/api/getUser", authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(
      "SELECT id, username, fingerprint_token FROM users WHERE id = $1",
      [req.user.userId]
    );
    const user = result.rows[0];
    client.release();

    if (!user) {
      return res
        .status(404)
        .json({ status: 404, message: "Usuario no encontrado" });
    }

    const hasFingerprintToken = user.fingerprint_token !== null;

    res
      .status(200)
      .json({
        status: 200,
        message: "Petición exitosa",
        user: user,
        hasFingerprintToken: hasFingerprintToken,
      });
  } catch (err) {
    console.error("Error al obtener la información del usuario", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Endpoint para agregar un dispositivo
app.post("/api/addDevice", authenticateToken, async (req, res) => {
  const { device_token } = req.body;

  const user_id = req.user.userId;

  try {
    const client = await pool.connect();

    // Verificar si el device_token ya existe
    const tokenExists = await client.query(
      "SELECT * FROM devices WHERE user_id = $1 AND device_token = $2",
      [user_id, device_token]
    );
    if (tokenExists.rows.length > 0) {
      client.release();
      return res.status(400).json({
        status: 400,
        message: "El token del dispositivo ya está registrado",
      });
    }

    // Insertar el nuevo dispositivo en la base de datos
    const result = await client.query(
      "INSERT INTO devices (user_id, device_token) VALUES ($1, $2) RETURNING *",
      [user_id, device_token]
    );

    client.release();

    res
      .status(201)
      .json({ status: 201, message: "Dispositivo agregado exitosamente" });
  } catch (err) {
    console.error("Error al agregar dispositivo", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Eliminar un dispositivo
app.delete("/api/deleteDevice", async (req, res) => {
  const { device_token, user_id } = req.body;

  try {
    const client = await pool.connect();

    const result = await client.query(
      "DELETE FROM devices WHERE user_id = $1 AND device_token = $2",
      [user_id, device_token]
    );

    client.release();

    if (result.rowCount > 0) {
      res.status(200).json({
        status: 200,
        message: "Dispositivo eliminado exitosamente",
      });
    } else {
      res.status(404).json({
        status: 404,
        message: "Dispositivo no encontrado",
      });
    }
  } catch (error) {
    console.error(error); // Asegúrate de registrar el error para depuración
    res.status(500).json({
      status: 500,
      message: "Error interno del servidor",
      error: error.message,
    });
  }
});

// Endpoint para obtener las notificaciones con detalles del usuario y dispositivo
app.get("/api/getNotifications", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const client = await pool.connect();
    const result = await client.query(
      `
    SELECT 
        n.title,
        n.body,
        n.image_url,
        n.data
    FROM 
        notifications n
    WHERE 
        n.user_id = $1
    ORDER BY
        n.date DESC`,
      [userId]
    );
    const notifications = result.rows;

    if (notifications.length === 0) {
      return res.status(404).json({
        status: 404,
        message:
          "No se encontraron notificaciones para el usuario especificado",
      });
    }

    client.release();
    res.status(200).json({
      status: 200,
      message: "Petición exitosa",
      notifications: notifications,
    });
  } catch (err) {
    console.error("Error al obtener notificaciones con detalles", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

// Endpoint para alternar la habilitación de la huella digital de un usuario
app.post("/api/toggleFingerprint", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { device_info_token } = req.body;

  if (!device_info_token) {
    return res.status(400).json({
      status: 400,
      message: "Falta el token de información del dispositivo",
    });
  }

  const fingerprintToken = uuidv5(device_info_token, namespace);

  try {
    const client = await pool.connect();

    // Obtener el usuario actual
    const userResult = await client.query(
      "SELECT fingerprint_token FROM users WHERE id = $1",
      [userId]
    );

    const currentFingerprintToken = userResult.rows[0].fingerprint_token;

    let newFingerprintToken = null;

    if (currentFingerprintToken) {
      newFingerprintToken = null;
    } else {
      newFingerprintToken = fingerprintToken;
    }

    // Actualizar el campo fingerprint_token para el usuario especificado
    const result = await client.query(
      "UPDATE users SET fingerprint_token = $1 WHERE id = $2 RETURNING *",
      [newFingerprintToken, userId]
    );

    client.release();

    if (result.rowCount > 0) {
      res.status(200).json({
        status: 200,
        message: `La huella digital ha sido ${
          newFingerprintToken ? "habilitada" : "deshabilitada"
        } exitosamente`,
      });
    } else {
      res.status(404).json({
        status: 404,
        message: "Usuario no encontrado",
      });
    }
  } catch (error) {
    console.error("Error al alternar la huella digital", error);
    res.status(500).json({
      status: 500,
      message: "Error interno del servidor",
      error: error.message,
    });
  }
});

// Endpoint para obtener usuarios con huella digital habilitada
app.get("/api/usersWithFingerprintToken", async (req, res) => {
  const { device_info_token } = req.body;

  if (!device_info_token) {
    return res.status(400).json({
      status: 400,
      message: "Falta el token de información del dispositivo",
    });
  }

  const fingerprintToken = uuidv5(device_info_token, namespace);

  try {
    const client = await pool.connect();

    // Consultar usuarios con huella digital habilitada
    const result = await client.query(
      "SELECT username, account_type FROM users WHERE fingerprint_token = $1",
      [fingerprintToken]
    );

    client.release();

    const users = result.rows;

    // Devolver la lista de usuarios con huella digital habilitada
    res.status(200).json({
      status: 200,
      message: "Usuarios con huella digital habilitada obtenidos exitosamente",
      users: users,
    });
  } catch (error) {
    console.error(
      "Error al obtener usuarios con huella digital habilitada",
      error
    );
    res.status(500).json({
      status: 500,
      message:
        "Error interno del servidor al obtener usuarios con huella digital habilitada",
      error: error.message,
    });
  }
});

// Endpoint para reiniciar las tablas users, devices y notifications
app.post("/api/resetTables", async (req, res) => {
  try {
    const client = await pool.connect();

    // Truncar las tablas y reiniciar los contadores de auto-incremento
    await client.query("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
    await client.query("TRUNCATE TABLE devices RESTART IDENTITY CASCADE");
    await client.query("TRUNCATE TABLE notifications RESTART IDENTITY CASCADE");

    client.release();

    res
      .status(200)
      .json({ status: 200, message: "Tablas reiniciadas correctamente" });
  } catch (err) {
    console.error("Error al reiniciar tablas", err);
    res
      .status(500)
      .json({ status: 500, message: "Error interno del servidor" });
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
