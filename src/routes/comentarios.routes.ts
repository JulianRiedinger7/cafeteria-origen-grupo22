import express from 'express';
import * as comentarios from '../services/comentarios.service';

const router = express.Router();

/**
 * GET /api/comentarios — reseñas públicas de la cafetería.
 * El sitio las pinta con innerHTML: por eso son un vector de XSS almacenado.
 */
router.get('/', async (req, res, next) => {
  try {
    res.json({ comentarios: await comentarios.listar() });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/comentarios
 *
 * FALLA: sin token anti-CSRF.
 *
 * La longitud y el rango de los datos se validan antes de guardarlos.
 */
router.post('/', async (req, res, next) => {
  try {
    const { autor, texto, calificacion } = req.body || {};

    if (
      typeof autor !== 'string' ||
      typeof texto !== 'string' ||
      typeof calificacion !== 'number'
    ) {
      return res.status(400).json({ error: 'Datos de la reseña inválidos.' });
    }

    const autorLimpio = autor.trim();
    const textoLimpio = texto.trim();
    if (
      autorLimpio.length < 2 ||
      autorLimpio.length > 40 ||
      textoLimpio.length < 3 ||
      textoLimpio.length > 280 ||
      !Number.isInteger(calificacion) ||
      calificacion < 1 ||
      calificacion > 5
    ) {
      return res.status(400).json({ error: 'Datos de la reseña inválidos.' });
    }

    const comentario = await comentarios.crear({
      autor: autorLimpio,
      texto: textoLimpio,
      calificacion,
    });
    res.status(201).json(comentario);
  } catch (err) {
    next(err);
  }
});

/** DELETE /api/comentarios/:id */
router.delete('/:id', async (req, res, next) => {
  try {
    // FALLA: sin verificación de rol — cualquiera puede borrar reseñas.
    const comentario = await comentarios.eliminar(req.params.id);
    if (!comentario) {
      return res.status(404).json({ error: 'Comentario no encontrado.' });
    }
    res.json(comentario);
  } catch (err) {
    next(err);
  }
});

export default router;
