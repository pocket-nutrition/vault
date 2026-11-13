from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.bodylimit import BodyLimitMiddleware
from sqlalchemy.orm import sessionmaker

from app.config import Settings
from app.db import make_engine, run_migrations
from app.accounts import router as accounts_router
from app.accounts import configure_argon
from app.ratelimit import RateLimiter, UnknownLoginGuard
from app.routes import admin_router, router


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    engine = make_engine(settings.database_url)
    run_migrations(engine)

    app = FastAPI(title="Pocket Nutrition Vault", version="0.1.0")
    app.state.settings = settings
    app.state.rate_limiter = RateLimiter()
    app.state.unknown_logins = UnknownLoginGuard()
    configure_argon(settings.argon_concurrency, settings.argon_wait_s)
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            allow_credentials=False,
            # A 429 says how long to wait in Retry-After; without this the page cannot read it.
            expose_headers=["Retry-After"],
            max_age=600,
        )
    app.state.session_factory = sessionmaker(engine, expire_on_commit=False)
    app.include_router(admin_router)
    app.include_router(accounts_router)
    app.include_router(router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/apple-app-site-association", include_in_schema=False)
    def apple_app_site_association() -> JSONResponse:
        apps = [part.strip() for part in settings.apple_app_ids.split(",") if part.strip()]
        if not apps:
            raise HTTPException(status_code=404)
        return JSONResponse({"webcredentials": {"apps": apps}})

    return app


def build() -> FastAPI:
    return create_app()
