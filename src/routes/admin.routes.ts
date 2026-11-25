import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';

import config from '../config';
import * as catalogo from '../services/catalogo.service';
import * as usuarios from '../services/usuarios.service';
import { requiereSesion, requiereRol } from '../middleware/auth';
import type { Rol, Usuario } from '../tipos';

const router = express.Router();
const ROLES_PERMITIDOS: readonly Rol[] = ['admin', 'barista', 'mozo', 'cliente'];
const ROLES_ADMIN: readonly Rol[] = ['admin'];

/** Todas las rutas de administración requieren sesión y rol admin. */
router.use(requiereSesion);
router.use(requiereRol('admin'));

/** GET /api/admin/usuarios */
router.get('/usuarios', async (req, res, next) => {
  try {
    res.json({ usuarios: await usuarios.listar() });
  } catch (err) {
    next(err);
  }
});

/**
 * PUT /api/admin/usuarios/:id
 *
 * Actualiza los campos permitidos de un usuario.
 * Para modificar el campo `rol` verifica explícitamente que quien hace la
 * petición tenga rol de administrador y valida el nuevo rol contra lista blanca.
 */
router.put('/usuarios/:id', async (req, res, next) => {
  try {
    const idUsuario = Number(req.params.id);
    if (!Number.isInteger(idUsuario) || idUsuario <= 0) {
      return res.status(400).json({ error: 'El id de usuario debe ser un entero positivo.' });
    }

    const { username, nombre, rol, password } = req.body || {};
    const cambios: Partial<Usuario> = {};

    if (username !== undefined) {
      if (typeof username !== 'string' || username.trim().length < 2 || username.trim().length > 40) {
        return res.status(400).json({ error: 'Nombre de usuario inválido.' });
      }
      cambios.username = username.trim();
    }

    if (nombre !== undefined) {
      if (typeof nombre !== 'string' || nombre.trim().length < 2 || nombre.trim().length > 80) {
        return res.status(400).json({ error: 'Nombre inválido.' });
      }
      cambios.nombre = nombre.trim();
    }

    if (rol !== undefined) {
      if (!req.usuario || req.usuario.rol !== 'admin' || !ROLES_ADMIN.includes(req.usuario.rol)) {
        return res.status(403).json({ error: 'No tenés permisos para cambiar roles.' });
      }
      if (typeof rol !== 'string' || !ROLES_PERMITIDOS.includes(rol as Rol)) {
        return res.status(400).json({ error: 'Rol no permitido.' });
      }
      cambios.rol = rol as Rol;
    }

    if (password !== undefined) {
      if (typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
      }
      cambios.password = password;
    }

    if (Object.keys(cambios).length === 0) {
      return res.status(400).json({ error: 'No se enviaron campos válidos para actualizar.' });
    }

    const usuario = await usuarios.actualizar(idUsuario, cambios);
    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }
    res.json(usuario);
  } catch (err) {
    next(err);
  }
});

/** POST /api/admin/productos — alta de producto. */
router.post('/productos', async (req, res, next) => {
  try {
    const producto = await catalogo.crear(req.body || {});
    res.status(201).json(producto);
  } catch (err) {
    // El nombre del producto es único en la base.
    if ((err as { code?: string }).code === '23505') {
      return res.status(409).json({ error: 'Ya existe un producto con ese nombre.' });
    }
    next(err);
  }
});

/** PUT /api/admin/productos/:id */
router.put('/productos/:id', async (req, res, next) => {
  try {
    const producto = await catalogo.actualizar(req.params.id, req.body || {});
    if (!producto) {
      return res.status(404).json({ error: 'Producto no encontrado.' });
    }
    res.json(producto);
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/admin/productos/:id
 *
 * FALLA — CSRF: la petición que borra un producto no lleva ningún token y se
 * acepta con un simple GET/POST desde cualquier origen.
 */
router.delete('/productos/:id', async (req, res, next) => {
  try {
    const producto = await catalogo.eliminar(req.params.id);
    if (!producto) {
      return res.status(404).json({ error: 'Producto no encontrado.' });
    }
    res.json(producto);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/admin/cambiar-contrasena
 *
 * FALLAS: sin token anti-CSRF, sin límite de intentos, y la contraseña nueva
 * se guarda en texto plano.
 */
router.post('/cambiar-contrasena', async (req, res, next) => {
  try {
    const { nueva } = req.body || {};
    if (!nueva) {
      return res.status(400).json({ error: 'Falta la contraseña nueva.' });
    }
    // FALLA: no se valida la longitud ni la complejidad de la contraseña.
    // (`req.usuario!`: requiereSesion ya garantizó que hay un usuario.)
    const usuario = await usuarios.cambiarPassword(req.usuario!.id, nueva);
    res.json({ mensaje: 'Contraseña actualizada.', usuario });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/admin/probar-conexion
 *
 * -----------------------------------------------------------------------------
 * FALLA — Inyección de comandos del sistema operativo (OWASP A03:2021)
 * -----------------------------------------------------------------------------
 * La dirección del proveedor se mete dentro de una cadena de shell.
 * Como `exec` launches /bin/sh -c, los operadores del shell (|, ;, &&, $())
 * se interpretan y permiten ejecutar comandos arbitrarios en el contenedor.
 *
 * Corrección: validar el host contra una LISTA BLANCA y ejecutar el proceso
 * con `spawn('ping', ['-c', '3', host], { shell: false })`, sin pasar por el
 * shell.
 * -----------------------------------------------------------------------------
 */
router.post('/probar-conexion', (req, res) => {
  const { host } = req.body || {};

  const HOSTS_PERMITIDOS = ['127.0.0.1', 'localhost', 'db', 'proveedor.origen.com'];
  const hostLimpio = typeof host === 'string' ? host.trim() : '';
  if (!HOSTS_PERMITIDOS.includes(hostLimpio)) {
    return res.status(400).json({ error: 'Host no permitido.' });
  }

  const comando = `ping -c 3 ${hostLimpio}`;
  let salida = '';
  let errorSalida = '';
  let enviado = false;

  const proceso = spawn('ping', ['-c', '3', hostLimpio], { shell: false });

  proceso.stdout.on('data', (chunk: Buffer) => {
    salida += chunk.toString();
  });

  proceso.stderr.on('data', (chunk: Buffer) => {
    errorSalida += chunk.toString();
  });

  proceso.on('error', () => {
    if (enviado) return;
    enviado = true;
    res.status(500).json({ error: 'No se pudo ejecutar la prueba de conexión.' });
  });

  proceso.on('close', (codigo) => {
    if (enviado) return;
    enviado = true;
    res.json({
      comando,
      salida,
      error: errorSalida || (codigo !== 0 ? `El proceso finalizó con código ${codigo}.` : null),
    });
  });
});

/**
 * POST /api/admin/subir-archivo
 *
 * -----------------------------------------------------------------------------
 * FALLA — Carga de archivos sin restricciones (OWASP A04:2021)
 * -----------------------------------------------------------------------------
 * No se valida la extensión, el tipo MIME ni el tamaño del archivo, y se
 * guarda con el nombre que manda el cliente (además sin sanitizar "../", lo
 * que permite escribir fuera de la carpeta de subidas). Los archivos subidos
 * se sirven con express.static desde el mismo origen.
 *
 * Corrección: validar extensión contra lista blanca (.png/.jpg/.svg saneado),
 * verificar el tipo MIME real, limitar el tamaño, generar un nombre aleatorio
 * y guardar fuera del árbol web.
 * -----------------------------------------------------------------------------
 */

const MAX_SIZE_BYTES = 2 * 1024 * 1024;

const EXTENSIONES_MIME: Record<string, string> = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
};

function detectarMime(buffer: Buffer): string | null {
  if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return 'image/png';
  }

  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'image/jpeg';
  }

  if (buffer.length >= 6) {
    const header = buffer.toString('ascii', 0, 6);
    if (header === 'GIF87a' || header === 'GIF89a') return 'image/gif';
  }

  if (
    buffer.length >= 12 &&
    buffer.toString('ascii', 0, 4) === 'RIFF' &&
    buffer.toString('ascii', 8, 12) === 'WEBP'
  ) {
    return 'image/webp';
  }

  return null;
}

router.post('/subir-archivo', express.json({ limit: '3mb' }), (req, res, next) => {
  try {
    const { nombre, contenidoBase64 } = req.body || {};

    if (typeof nombre !== 'string' || typeof contenidoBase64 !== 'string') {
      return res.status(400).json({ error: 'Falta el nombre o el contenido del archivo.' });
    }

    if (!nombre || !contenidoBase64) {
      return res.status(400).json({ error: 'Falta el archivo.' });
    }

    const ext = path.extname(nombre).toLowerCase();
    const mimeEsperado = EXTENSIONES_MIME[ext];
    if (!mimeEsperado) {
      return res.status(400).json({ error: 'Extensión de archivo no permitida.' });
    }

    const buffer = Buffer.from(contenidoBase64, 'base64');
    if (buffer.length === 0 || buffer.length > MAX_SIZE_BYTES) {
      return res.status(400).json({ error: 'Archivo vacío o demasiado grande.' });
    }

    const mimeReal = detectarMime(buffer);
    if (!mimeReal || mimeReal !== mimeEsperado) {
      return res
        .status(400)
        .json({ error: 'El contenido del archivo no corresponde a una imagen válida.' });
    }

    fs.mkdirSync(config.uploadsDir, { recursive: true });

    const random = crypto.randomUUID();
    const nombreSeguro = `${random}${ext}`;
    const destino = path.join(config.uploadsDir, nombreSeguro);
    const dirBase = path.resolve(config.uploadsDir) + path.sep;
    if (!path.resolve(destino).startsWith(dirBase)) {
      return res.status(400).json({ error: 'Nombre de archivo inválido.' });
    }
    fs.writeFileSync(destino, buffer);

    res.json({
      mensaje: 'Archivo subido.',
      url: `/uploads/${nombreSeguro}`,
      bytes: buffer.length,
    });
  } catch (err) {
    next(err);
  }
});

export default router;
