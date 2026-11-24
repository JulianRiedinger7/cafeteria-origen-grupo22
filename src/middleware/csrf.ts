import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';

import config from '../config';
import { leerCookies } from './sesion';

const NOMBRE_COOKIE_CSRF = 'csrf';
const METODOS_SEGUROS = new Set(['GET', 'HEAD', 'OPTIONS']);
const RUTAS_EXENTAS_TOKEN = new Set(['/auth/login']);
const SECRETO_EFIMERO = crypto.randomBytes(32).toString('hex');

function secretoCsrf(): string {
  return config.sessionSecret || SECRETO_EFIMERO;
}

function contextoSesion(req: Request): string {
  const cookies = leerCookies(req);
  return cookies.sid ? `sid:${cookies.sid}` : 'anon';
}

function firmar(token: string, contexto: string): string {
  return crypto.createHmac('sha256', secretoCsrf()).update(`${contexto}:${token}`).digest('hex');
}

function compararSeguro(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function extraerTokenCookieValido(
  valorCookie: string | undefined,
  contexto: string,
): string | null {
  if (!valorCookie) return null;
  const partes = valorCookie.split('.');
  if (partes.length !== 2) return null;

  const [token, firma] = partes;
  if (!/^[0-9a-f]{64}$/.test(token) || !/^[0-9a-f]{64}$/.test(firma)) return null;

  const firmaEsperada = firmar(token, contexto);
  return compararSeguro(firma, firmaEsperada) ? token : null;
}

function leerTokenEnviado(req: Request): string | null {
  const header = req.get('x-csrf-token');
  if (typeof header === 'string' && header.length > 0) return header;

  const cuerpo = req.body as Record<string, unknown> | undefined;
  if (cuerpo && typeof cuerpo._csrf === 'string' && cuerpo._csrf.length > 0) {
    return cuerpo._csrf;
  }

  const query = req.query as Record<string, unknown> | undefined;
  if (query && typeof query._csrf === 'string' && query._csrf.length > 0) {
    return query._csrf;
  }

  return null;
}

function origenValido(req: Request): boolean {
  const host = req.get('host');
  if (!host) return true;

  const origin = req.headers.origin;
  if (typeof origin === 'string') {
    try {
      return new URL(origin).host === host;
    } catch {
      return false;
    }
  }

  const referer = req.headers.referer;
  if (typeof referer === 'string') {
    try {
      return new URL(referer).host === host;
    } catch {
      return false;
    }
  }

  return true;
}

export function emitirTokenCsrf(req: Request, res: Response): void {
  const contexto = contextoSesion(req);
  const cookies = leerCookies(req);
  let token = extraerTokenCookieValido(cookies[NOMBRE_COOKIE_CSRF], contexto);

  if (!token) {
    token = crypto.randomBytes(32).toString('hex');
  }

  const valorCookie = `${token}.${firmar(token, contexto)}`;
  res.cookie(NOMBRE_COOKIE_CSRF, valorCookie, {
    path: '/',
    httpOnly: true,
    secure: config.nodeEnv === 'production',
    sameSite: 'lax',
  });

  res.json({ token });
}

export function verificarCsrf(req: Request, res: Response, next: NextFunction): void {
  if (METODOS_SEGUROS.has(req.method.toUpperCase())) {
    next();
    return;
  }

  if (!origenValido(req)) {
    res.status(403).json({ error: 'Origen de la petición no permitido.' });
    return;
  }

  if (RUTAS_EXENTAS_TOKEN.has(req.path)) {
    next();
    return;
  }

  const contexto = contextoSesion(req);
  const cookies = leerCookies(req);
  const tokenCookie = extraerTokenCookieValido(cookies[NOMBRE_COOKIE_CSRF], contexto);
  const tokenEnviado = leerTokenEnviado(req);

  if (!tokenCookie || !tokenEnviado || !compararSeguro(tokenCookie, tokenEnviado)) {
    res.status(403).json({ error: 'Token anti-CSRF inválido o ausente.' });
    return;
  }

  next();
}
