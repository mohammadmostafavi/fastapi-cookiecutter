"""
Security middleware.

This module provides middleware for implementing security features such as
CORS, security headers, and Content Security Policy.
"""

from typing import List, Dict, Optional, Union
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from src.config import settings


def add_cors_middleware(app: FastAPI) -> None:
    """
    Add CORS middleware to the FastAPI application.
    
    Args:
        app: The FastAPI application
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
        expose_headers=settings.cors_expose_headers,
        max_age=settings.cors_max_age,
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware for adding security headers to responses.
    
    This middleware adds various security headers to HTTP responses to enhance
    the security of the application.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process the request and add security headers to the response.
        
        Args:
            request: The incoming request
            call_next: The next middleware or route handler
            
        Returns:
            The response with added security headers
        """
        # Process the request
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Add Content Security Policy header if enabled
        if settings.csp_enabled:
            response.headers["Content-Security-Policy"] = self._build_csp_header()
            
        return response
        
    def _build_csp_header(self) -> str:
        """
        Build the Content Security Policy header value.
        
        Returns:
            The CSP header value as a string
        """
        directives = []
        
        # Add default directives
        directives.append(f"default-src {' '.join(settings.csp_default_src)}")
        
        # Add script-src directive if configured
        if settings.csp_script_src:
            directives.append(f"script-src {' '.join(settings.csp_script_src)}")
            
        # Add style-src directive if configured
        if settings.csp_style_src:
            directives.append(f"style-src {' '.join(settings.csp_style_src)}")
            
        # Add img-src directive if configured
        if settings.csp_img_src:
            directives.append(f"img-src {' '.join(settings.csp_img_src)}")
            
        # Add connect-src directive if configured
        if settings.csp_connect_src:
            directives.append(f"connect-src {' '.join(settings.csp_connect_src)}")
            
        # Add font-src directive if configured
        if settings.csp_font_src:
            directives.append(f"font-src {' '.join(settings.csp_font_src)}")
            
        # Add object-src directive if configured
        if settings.csp_object_src:
            directives.append(f"object-src {' '.join(settings.csp_object_src)}")
            
        # Add media-src directive if configured
        if settings.csp_media_src:
            directives.append(f"media-src {' '.join(settings.csp_media_src)}")
            
        # Add frame-src directive if configured
        if settings.csp_frame_src:
            directives.append(f"frame-src {' '.join(settings.csp_frame_src)}")
            
        # Add report-uri directive if configured
        if settings.csp_report_uri:
            directives.append(f"report-uri {settings.csp_report_uri}")
            
        return "; ".join(directives)


def add_security_headers_middleware(app: FastAPI) -> None:
    """
    Add security headers middleware to the FastAPI application.
    
    Args:
        app: The FastAPI application
    """
    app.add_middleware(SecurityHeadersMiddleware)