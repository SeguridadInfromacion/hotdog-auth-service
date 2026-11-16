# hotdog-auth-service

Servicio de autenticación de **PerroCaliente Express**: inicio de sesión,
administración de usuarios y emisión de los tokens que los demás servicios verifican.

Python 3.12, FastAPI, SQLAlchemy, PostgreSQL.
Documentación general: [hotdog-docs](https://github.com/SeguridadInfromacion/hotdog-docs).

## API

| Método | Ruta | Quién | Qué hace |
|---|---|---|---|
| POST | `/api/auth/login` | cualquiera | Inicia sesión y entrega la cookie de sesión |
| POST | `/api/auth/refresh` | con sesión | Cambia el token vigente por uno nuevo |
| POST | `/api/auth/logout` | cualquiera | Invalida el token y borra la cookie |
| GET | `/api/auth/me` | con sesión | Usuario actual |
| GET | `/api/auth/audit` | admin | Bitácora de este servicio |
| GET | `/api/users` | admin | Lista de usuarios |
| POST | `/api/users` | admin | Crea un usuario |
| PATCH | `/api/users/{id}` | admin | Edita nombre, rol, estado o contraseña |

## Decisiones de seguridad

- **Argon2id** para las contraseñas. Nunca se guardan ni se devuelven.
- **JWT RS256.** Este es el único servicio con la llave privada. El algoritmo
  está fijo: se rechazan `alg: none` y la confusión RS256/HS256.
- **Cookie `HttpOnly; Secure; SameSite=Strict`.** El token no aparece en el
  cuerpo de la respuesta y el JavaScript no puede leerlo.
- **Sin enumeración de usuarios.** Mismo mensaje y mismo tiempo de respuesta
  exista o no el usuario, esté o no bloqueado.
- **Bloqueo por usuario + IP** de 15 minutos tras 5 intentos fallidos. Al ser
  por pareja, un extraño no puede dejar por fuera al dueño de la cuenta.
- **Tokens cortos y revocables.** Duran 10 minutos y se renuevan solos hasta un
  tope de 10 horas. Cerrar sesión, cambiar la contraseña o el rol, o desactivar
  al usuario invalida los tokens que ya tenía.
- **Los errores de validación no devuelven lo enviado**, que podría ser una contraseña.
- **Entradas estrictas.** Pydantic valida todo y rechaza campos desconocidos.
- **Auditoría** de cada inicio de sesión (correcto o fallido) y cada cambio de usuarios.

## Estructura

```
app/
  main.py          arranque, manejo de errores
  routes.py        HTTP  -> casos de uso
  services.py      casos de uso (reglas de negocio)
  repositories.py  acceso a datos
  models.py        tablas
  schemas.py       contratos de entrada y salida
  security.py      contraseñas y tokens
  dependencies.py  sesión, usuario actual, roles, anti-CSRF
  config.py        variables de entorno
tests/             pruebas (incluye ataques con tokens manipulados)
```

## Desarrollo

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

pytest              # pruebas (usan SQLite en memoria, no necesitan Docker)
ruff check .        # estilo y errores comunes
bandit -r app       # análisis de seguridad
pip-audit -r requirements.txt   # dependencias vulnerables
```

Para ejecutarlo junto al resto del sistema, usa
[hotdog-infra](https://github.com/SeguridadInfromacion/hotdog-infra).

## Variables de entorno

| Variable | Obligatoria | Descripción |
|---|---|---|
| `DATABASE_URL` | sí | Conexión a PostgreSQL |
| `JWT_PRIVATE_KEY_FILE` | sí | Ruta a la llave privada RSA (PEM) |
| `JWT_PUBLIC_KEY_FILE` | sí | Ruta a la llave pública RSA (PEM) |
| `ACCESS_TOKEN_MINUTES` | no (10) | Duración de cada token |
| `SESSION_HOURS` | no (10) | Tope absoluto de una sesión, aunque se renueve |
| `FORWARDED_ALLOW_IPS` | no | Dirección del gateway: solo a él se le cree la IP del cliente |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | con la base vacía | Administrador inicial; sin ellos el servicio no arranca |
| `DEMO_CASHIER_USERNAME`, `DEMO_CASHIER_PASSWORD` | no | Cajero inicial, si no hay usuarios |
| `ENABLE_DOCS` | no (false) | Activa `/docs` (solo para desarrollo) |
