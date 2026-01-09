"""
HTTP Module Executor - Execute YAML-based HTTP modules.
Ported from sif's Go executor.
"""

import asyncio
from dataclasses import dataclass
from typing import Any

from .http_client import AsyncHTTPClient, HTTPResponse, get_http_client
from .module import Finding, ModuleOptions, ModuleResult, Severity
from .yaml_modules import (
    HTTPConfig,
    YAMLModule,
    check_matchers,
    run_extractors,
    substitute_variables,
    truncate_evidence,
)

MAX_BODY_SIZE = 5 * 1024 * 1024  # 5MB


@dataclass
class HTTPRequest:
    """Generated HTTP request"""
    method: str
    url: str
    headers: dict[str, str]
    body: str
    payload: str
    original: str  # Original path template


def generate_http_requests(target: str, config: HTTPConfig) -> list[HTTPRequest]:
    """
    Generate all requests based on paths and payloads.
    
    Args:
        target: Base URL target
        config: HTTP configuration
        
    Returns:
        List of generated requests
    """
    requests: list[HTTPRequest] = []
    
    # Ensure no trailing slash
    target = target.rstrip("/")
    method = config.method or "GET"
    
    # If no payloads, just use paths directly
    if not config.payloads:
        for path in config.paths:
            url = substitute_variables(path, target)
            requests.append(HTTPRequest(
                method=method,
                url=url,
                headers=config.headers.copy(),
                body=config.body,
                payload="",
                original=path,
            ))
        return requests
    
    # Generate requests with payloads
    for path in config.paths:
        for payload in config.payloads:
            url = substitute_variables(path, target, payload)
            body = substitute_variables(config.body, target, payload)
            requests.append(HTTPRequest(
                method=method,
                url=url,
                headers=config.headers.copy(),
                body=body,
                payload=payload,
                original=path,
            ))
    
    return requests


async def execute_http_request(
    client: AsyncHTTPClient,
    request: HTTPRequest,
    config: HTTPConfig,
    severity: Severity,
) -> Finding | None:
    """
    Execute a single HTTP request and check matchers.
    
    Returns Finding if matchers pass, None otherwise.
    """
    try:
        if request.method.upper() == "GET":
            response = await client.get(request.url, headers=request.headers)
        elif request.method.upper() == "POST":
            response = await client.post(
                request.url,
                headers=request.headers,
                data={"body": request.body} if request.body else None,
            )
        else:
            # Default to GET for other methods
            response = await client.get(request.url, headers=request.headers)
        
        if response.error:
            return None
        
        # Check matchers
        if not check_matchers(
            config.matchers,
            response.status_code,
            response.headers,
            response.text[:MAX_BODY_SIZE],
        ):
            return None
        
        # Run extractors
        extracted = run_extractors(
            config.extractors,
            response.headers,
            response.text,
        )
        
        return Finding(
            url=request.url,
            severity=severity,
            evidence=truncate_evidence(response.text),
            extracted=extracted,
        )
        
    except Exception:
        return None


async def execute_http_module(
    target: str,
    module: YAMLModule,
    opts: ModuleOptions | None = None,
) -> ModuleResult:
    """
    Execute an HTTP-based YAML module.
    
    Args:
        target: Target URL
        module: YAML module definition
        opts: Execution options
        
    Returns:
        ModuleResult with findings
    """
    if module.http is None:
        raise ValueError("Module has no HTTP configuration")
    
    opts = opts or ModuleOptions()
    config = module.http
    
    result = ModuleResult(
        module_id=module.id,
        target=target,
        findings=[],
    )
    
    # Create HTTP client
    client = get_http_client(
        timeout=opts.timeout,
        user_agent=opts.user_agent,
        verify_ssl=opts.verify_ssl,
        follow_redirects=opts.follow_redirects,
    )
    
    # Generate requests
    requests = generate_http_requests(target, config)
    
    # Determine thread count
    threads = config.threads or opts.threads or 10
    
    # Execute requests concurrently
    semaphore = asyncio.Semaphore(threads)
    findings: list[Finding] = []
    lock = asyncio.Lock()
    
    async def process_request(req: HTTPRequest) -> None:
        async with semaphore:
            finding = await execute_http_request(
                client, req, config, module.severity
            )
            if finding:
                async with lock:
                    findings.append(finding)
    
    await asyncio.gather(*[process_request(req) for req in requests])
    
    result.findings = findings
    return result


async def execute_yaml_module(
    target: str,
    module: YAMLModule,
    opts: ModuleOptions | None = None,
) -> ModuleResult:
    """
    Execute a YAML module (routes to appropriate executor).
    """
    from .module import ModuleType
    
    if module.module_type == ModuleType.HTTP:
        return await execute_http_module(target, module, opts)
    else:
        # DNS and TCP not yet implemented
        return ModuleResult(
            module_id=module.id,
            target=target,
            findings=[],
        )
