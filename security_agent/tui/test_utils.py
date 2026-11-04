"""
Test utilities for Qwythos TUI testing.
Provides thread-safe, isolated coroutine execution compatible with any pytest runner.
"""

import asyncio
import concurrent.futures
from typing import Coroutine, Any, TypeVar

T = TypeVar("T")


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """
    Executes a coroutine safely, creating an isolated event loop in a worker thread
    if the main thread already has an active running event loop.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)
