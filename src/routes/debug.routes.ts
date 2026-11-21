import express from 'express';
import { requiereRol, requiereSesion } from '../middleware/auth';
import config from '../config';

const router = express.Router();

/**
 * Endpoint de diagnóstico.
 *
 * -----------------------------------------------------------------------------
 * FALLA — Exposición de información sensible (OWASP A01:2021 / A05:2021)
 * -----------------------------------------------------------------------------
 * Devuelve el contenido completo de `process.env`: credenciales de la base de
 * datos, secretos, configuración interna... y NO requiere autenticación.
 *
 * En un entorno real estos endpoints quedan detrás de autenticación y no
 * deberían existir en producción.
 */
router.get('/', requiereSesion, requiereRol('admin'), (req, res) => {
  if (config.nodeEnv === 'production') {
    return res.status(404).json({
      error: 'Ruta no encontrada.',
    });
  }

  res.json({
    estado: 'ok',
    version: '1.0.0',
    uptime: process.uptime(),
  });
});

export default router;
