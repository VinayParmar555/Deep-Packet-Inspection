import logging
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from app.schema.packet_schema import PacketSchema
from app.services.dpi_engine import DPIEngine


# Custom exceptions
class PacketIngestionError(Exception):
    """Raised when packet ingestion fails in the DPI engine."""
    def __init__(self, message: str, detail: str = None):
        self.message = message
        self.detail = detail
        super().__init__(self.message)


class PacketValidationError(Exception):
    """Raised when packet data is invalid."""
    def __init__(self, message: str, errors: list = None):
        self.message = message
        self.errors = errors or []
        super().__init__(self.message)


# Standardized error response helper
def error_response(status_code: int, error: str, message: str, detail=None) -> JSONResponse:
    content = {
        "status": "error",
        "error": error,
        "message": message,
    }
    if detail:
        content["detail"] = detail
    return JSONResponse(status_code=status_code, content=content)


def create_router(engine: DPIEngine) -> APIRouter:
    router = APIRouter(prefix="", tags=["Packet Processing"])

    @router.post(
        "/ingest",
        status_code=status.HTTP_200_OK,
        responses={
            400: {"description": "Invalid packet data"},
            422: {"description": "Validation error"},
            500: {"description": "Internal server error"},
            503: {"description": "DPI engine unavailable"},
        },
    )
    async def ingest(packet: PacketSchema, request: Request):
        """
        Ingest a network packet into the DPI engine for deep packet inspection.
        """
        client_ip = request.client.host if request.client else "unknown"

        # --- Engine availability check ---
        if engine is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "ServiceUnavailable",
                    "message": "DPI engine is not available. Please try again later.",
                },
            )

        try:
            result = await engine.ingest_packet(packet)
            return {
                "status": "success",
                "message": "Packet ingested successfully",
                "data": result,
            }

        except PacketValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "PacketValidationError",
                    "message": e.message,
                    "errors": e.errors,
                },
            )

        except PacketIngestionError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "PacketIngestionError",
                    "message": e.message,
                    "detail": e.detail,
                },
            )

        except ValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "ValidationError",
                    "message": "Packet schema validation failed",
                    "errors": e.errors(),
                },
            )

        except TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail={
                    "error": "EngineTimeout",
                    "message": "DPI engine timed out. Please retry.",
                },
            )

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "InternalServerError",
                    "message": "An unexpected error occurred. Please contact support.",
                },
            )

    return router

def register_exception_handlers(app):
    """Register global exception handlers on the FastAPI app instance."""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": "error",
                "code": exc.status_code,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(ValidationError)
    async def validation_exception_handler(request: Request, exc: ValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "status": "error",
                "error": "ValidationError",
                "message": "Request body validation failed",
                "errors": exc.errors(),
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "error": "InternalServerError",
                "message": "An unexpected error occurred.",
            },
        )