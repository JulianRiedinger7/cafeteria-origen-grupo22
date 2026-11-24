import crypto from 'crypto';
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
 * FALLA — Almacenamiento inseguro de credenciales:
 * las contraseñas de los usuarios se guardan en TEXTO PLANO.
 * La corrección es hashear con bcrypt + salt por usuario
 * (bcryptjs ya está instalado como dependencia del proyecto).
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
      // FALLA: la contraseña se guarda tal cual, sin hash ni salt.
      const { rowCount } = await db.query(
        `INSERT INTO usuarios (username, password, rol, nombre)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (username) DO NOTHING`,
        [usuario.username, password, usuario.rol, usuario.nombre],
      );
      if (rowCount && claveGenerada && config.nodeEnv === 'development') {
        console.log(`[init] Usuario "${usuario.username}" creado con clave temporal: ${password}`);
      }
    }
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
