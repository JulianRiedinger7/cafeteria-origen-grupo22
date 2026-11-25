/**
 * Gestión de sesiones.
 *
 * Usa crypto.randomUUID() para generar identificadores aleatorios,
 * regenera el identificador tras el login, establece expiración por
 * inactividad y absoluta, configura la cookie con httpOnly/secure/sameSite
 * e invalida la sesión en el servidor al cerrar sesión.
 */

import type { Request, Response } from 'express';

import type { Sesion, UsuarioSesion } from '../tipos';

import { randomUUID } from 'node:crypto';

export const sesiones = new Map<string, Sesion>();
const TTL_INACTIVIDAD = 30 * 60 * 1000;
const MAX_VIDA = 8 * 60 * 60 * 1000;

/** Lee las cookies de la petición (parser mínimo, sin dependencias). */
export function leerCookies(req: Request): Record<string, string> {
  const cookies: Record<string, string> = {};
  const header = req.headers.cookie;
  if (!header) return cookies;
  for (const parte of header.split(';')) {
    const separador = parte.indexOf('=');
    if (separador < 0) continue;
    const nombre = parte.slice(0, separador).trim();
    const valor = parte.slice(separador + 1).trim();
    if (nombre) cookies[nombre] = decodeURIComponent(valor);
  }
  return cookies;
}

/** Crea una sesión nueva para el usuario y setea la cookie. */
export function crearSesion(req: Request, res: Response, usuario: UsuarioSesion): string {
  const sidAnterior = leerCookies(req).sid;
  if (sidAnterior) sesiones.delete(sidAnterior);

  const id = randomUUID();

  sesiones.set(id, {
    usuario,
    creadaEn: Date.now(),
    expiraEn: Date.now() + TTL_INACTIVIDAD,
  });

  res.cookie('sid', id, {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: MAX_VIDA,
  });

  return id;
}

/** Devuelve la sesión de la petición, si existe. */
export function obtenerSesion(req: Request): Sesion | null {
  const cookies = leerCookies(req);
  const id = cookies.sid;
  if (!id) return null;

  const sesion = sesiones.get(id);
  if(!sesion) return null; 

  const ahora = Date.now();
  const expiraEn = sesion.expiraEn ?? 0;

  if (ahora >= expiraEn || ahora - sesion.creadaEn >= MAX_VIDA) {
    sesiones.delete(id);
    return null;
  }

  sesion.expiraEn = ahora + TTL_INACTIVIDAD;
  return sesion;
}

/** Cierra la sesión en el servidor (debería llamarse en el logout). */
export function destruirSesion(req: Request): void {
  const cookies = leerCookies(req);
  const id = cookies.sid;
  if (id) sesiones.delete(id);
}
