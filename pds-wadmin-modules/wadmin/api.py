"""
PDS API client for making authenticated requests.
"""

import base64
import requests
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class APIResponse:
    """Wrapper for API responses with consistent error handling."""

    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    status_code: Optional[int] = None

    def require_success(self) -> Dict[str, Any]:
        """
        Ensure the response was successful, raising an exception if not.

        Returns:
            Response data dictionary

        Raises:
            RuntimeError: If the API call failed
        """
        if not self.success:
            error_msg = self.error or "Unknown error"
            raise RuntimeError(f"API call failed: {error_msg}")
        return self.data or {}


class PDSClient:
    """
    Client for making authenticated API calls to PDS.

    Uses HTTP Basic authentication with admin:password.
    """

    def __init__(self, host: str, admin_password: str):
        """
        Initialize PDS API client.

        Args:
            host: PDS host URL (e.g., https://pds-dev.wsocial.dev)
            admin_password: Admin password for authentication
        """
        self.host = host.rstrip("/")
        self.admin_password = admin_password
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
        })
        # Set up HTTP Basic auth with username "admin"
        self.session.auth = ("admin", admin_password)

    def call(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> APIResponse:
        """
        Make an authenticated API call to PDS.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., "io.trustanchor.admin.listInvitations")
            data: Request body data (for POST/PUT)
            params: Query parameters (for GET)

        Returns:
            APIResponse with success status and data/error
        """
        url = f"{self.host}/xrpc/{endpoint}"

        try:
            if method == "GET":
                response = self.session.get(
                    url,
                    params=params,
                    timeout=30,
                )
            elif method == "POST":
                response = self.session.post(
                    url,
                    json=data,
                    timeout=30,
                )
            elif method == "PUT":
                response = self.session.put(
                    url,
                    json=data,
                    timeout=30,
                )
            elif method == "DELETE":
                response = self.session.delete(
                    url,
                    json=data,
                    timeout=30,
                )
            else:
                return APIResponse(
                    success=False,
                    error=f"Unsupported HTTP method: {method}",
                )

            # Check for HTTP errors
            response.raise_for_status()

            # Parse JSON response (handle empty responses)
            if response.status_code == 204 or not response.content:
                # No content response - treat as success
                return APIResponse(
                    success=True,
                    data=None,
                    status_code=response.status_code,
                )

            try:
                result = response.json()
            except ValueError:
                # Not JSON response - but check if successful status code
                if 200 <= response.status_code < 300:
                    # Successful but non-JSON response (treat as void)
                    return APIResponse(
                        success=True,
                        data=None,
                        status_code=response.status_code,
                    )
                return APIResponse(
                    success=False,
                    error=f"Invalid JSON response from server",
                    status_code=response.status_code,
                )

            # Check for application-level errors
            if isinstance(result, dict) and "error" in result:
                return APIResponse(
                    success=False,
                    error=result.get("message", result.get("error", "Unknown error")),
                    status_code=response.status_code,
                )

            return APIResponse(
                success=True,
                data=result,
                status_code=response.status_code,
            )

        except requests.exceptions.HTTPError as e:
            # HTTP error (4xx, 5xx)
            error_msg = str(e)
            if e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get("message", error_data.get("error", str(e)))
                except ValueError:
                    pass

            return APIResponse(
                success=False,
                error=error_msg,
                status_code=e.response.status_code if e.response else None,
            )

        except requests.exceptions.Timeout:
            return APIResponse(
                success=False,
                error="Request timed out",
            )

        except requests.exceptions.ConnectionError as e:
            return APIResponse(
                success=False,
                error=f"Connection error: {e}",
            )

        except Exception as e:
            return APIResponse(
                success=False,
                error=f"Unexpected error: {e}",
            )
