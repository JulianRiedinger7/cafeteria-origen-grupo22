import bcrypt from 'bcryptjs';
import * as db from '../db';
import type { Usuario } from '../tipos';

/**
 * Servicio de usuarios.
 */

/** Busca un usuario por nombre de usuario exacto (query parametrizada). */
export async function buscarPorUsername(username: string): Promise<Usuario | null> {
  const { rows } = await db.query<Usuario>('SELECT * FROM usuarios WHERE username = $1', [
    username,
  ]);
  return rows[0] || null;
}

/**
 * Autentica a un usuario comparando usuario y contraseña.
 * Devuelve el usuario o null.
 */
export async function autenticar(username: string, password: string): Promise<Usuario | null> {
  const usuario = await buscarPorUsername(username);
  if (!usuario || !(await bcrypt.compare(password, usuario.password))) return null;
  return usuario;
}

/** Lista todos los usuarios (para el panel de administración). */
export async function listar(): Promise<Usuario[]> {
  const { rows } = await db.query<Usuario>('SELECT * FROM usuarios ORDER BY id');
  return rows;
}

const CAMPOS_ACTUALIZABLES = new Set(['username', 'nombre', 'rol', 'password']);

/**
 * Actualiza los campos permitidos de un usuario (lista blanca de columnas).
 */
export async function actualizar(
  id: number | string,
  cambios: Partial<Usuario>,
): Promise<Usuario | null> {
  const campos: string[] = [];
  const valores: unknown[] = [];
  let i = 1;
  for (const [campo, valor] of Object.entries(cambios)) {
    if (!CAMPOS_ACTUALIZABLES.has(campo)) continue;
    campos.push(`${campo} = $${i}`);
    valores.push(
      campo === 'password' && typeof valor === 'string'
        ? await bcrypt.hash(valor, 12)
        : valor,
    );
    i += 1;
  }
  if (campos.length === 0) return null;
  valores.push(id);
  const { rows } = await db.query<Usuario>(
    `UPDATE usuarios SET ${campos.join(', ')} WHERE id = $${i} RETURNING *`,
    valores,
  );
  return rows[0] || null;
}

/** Cambia la contraseña de un usuario. */
export async function cambiarPassword(id: number, nuevaPassword: string): Promise<Usuario | null> {
  const passwordHash = await bcrypt.hash(nuevaPassword, 12);
  const { rows } = await db.query<Usuario>(
    'UPDATE usuarios SET password = $1 WHERE id = $2 RETURNING *',
    [passwordHash, id],
  );
  return rows[0] || null;
}
