import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import * as db from './db';
import { CATALOGO } from './catalogo';
import type { Rol } from './tipos';
import config from './config';

interface UsuarioInicial {
  username: string;
  password?: string;
  rol: Rol;
  nombre: string;
}

/**
 * Carga los datos iniciales (usuarios y catálogo) si la base está vacía.
 *
 * Las contraseñas nuevas se guardan con bcrypt. Las cuentas antiguas en texto
 * plano se migran aquí de forma idempotente, preservando la clave original.
 */

export const USUARIOS_INICIALES: UsuarioInicial[] = [
  {
    username: 'admin',
    password: config.adminPassword,
    rol: 'admin',
    nombre: 'Administración',
  },
  {
    username: 'valentina',
    password: config.valentinaPassword,
    rol: 'admin',
    nombre: 'Valentina',
  },
  {
    username: 'barista',
    password: config.baristaPassword,
    rol: 'barista',
    nombre: 'Barista',
  },
  {
    username: 'mozo',
    password: config.mozoPassword,
    rol: 'mozo',
    nombre: 'Mozo de sala',
  },
  {
    username: 'cliente',
    password: config.clientePassword,
    rol: 'cliente',
    nombre: 'Cliente',
  },
];

export async function inicializarBase(): Promise<void> {
  // --- Usuarios -------------------------------------------------------------
  if (config.nodeEnv !== 'production') {
    for (const usuario of USUARIOS_INICIALES) {
      const claveGenerada = !usuario.password;
      const password = usuario.password || crypto.randomBytes(12).toString('base64url');
      const passwordHash = await bcrypt.hash(password, 12);
      const { rowCount } = await db.query(
        `INSERT INTO usuarios (username, password, rol, nombre)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (username) DO NOTHING`,
        [usuario.username, passwordHash, usuario.rol, usuario.nombre],
      );
      if (rowCount && claveGenerada && config.nodeEnv === 'development') {
        console.log(`[init] Usuario "${usuario.username}" creado con clave temporal: ${password}`);
      }
    }
  }

  const { rows: usuarios } = await db.query<{ id: number; password: string }>(
    'SELECT id, password FROM usuarios',
  );
  for (const usuario of usuarios) {
    if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(usuario.password)) continue;
    const passwordHash = await bcrypt.hash(usuario.password, 12);
    await db.query('UPDATE usuarios SET password = $1 WHERE id = $2', [
      passwordHash,
      usuario.id,
    ]);
  }

  // --- Catálogo -------------------------------------------------------------
  for (const producto of CATALOGO) {
    await db.query(
      `INSERT INTO productos
         (nombre, tipo, variedad, tamano, gramos, precio_base, precio_por_gramo, descripcion)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (nombre) DO NOTHING`,
      [
        producto.nombre,
        producto.tipo,
        producto.variedad,
        producto.tamano,
        producto.gramos,
        producto.precio_base,
        producto.precio_por_gramo,
        producto.descripcion,
      ],
    );
  }
}
