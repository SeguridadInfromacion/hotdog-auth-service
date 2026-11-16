"""Errores de negocio. main.py los traduce a respuestas HTTP."""


class AppError(Exception):
    status_code = 400
    detail = "Solicitud inválida."

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.detail)
        if detail:
            self.detail = detail


class NotAuthenticated(AppError):
    status_code = 401
    detail = "Debes iniciar sesión."


class InvalidCredentials(AppError):
    status_code = 401
    # Mensaje único a propósito: no revela si el usuario existe ni si está bloqueado.
    detail = (
        "Usuario o contraseña incorrectos. "
        "Tras varios intentos fallidos la cuenta se bloquea unos minutos."
    )


class PermissionDenied(AppError):
    status_code = 403
    detail = "No tienes permiso para hacer esto."


class NotFound(AppError):
    status_code = 404
    detail = "No encontrado."


class Conflict(AppError):
    status_code = 409
    detail = "Ya existe."
