"""
Worker Pool - Generic concurrent task processor.
Ported from sif's Go worker pool with Python async.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


class WorkerPool:
    """
    Async worker pool for concurrent task processing.
    
    Features:
    - Configurable concurrency
    - Optional filtering
    - Callback support for streaming results
    """

    def __init__(
        self,
        workers: int,
        fn: Callable[[T], Awaitable[R]],
    ):
        """
        Create a new worker pool.
        
        Args:
            workers: Number of concurrent workers
            fn: Async function to process each item
        """
        self.workers = max(1, workers)
        self.fn = fn

    async def run(self, items: list[T]) -> list[R]:
        """
        Process all items concurrently and return results.
        
        Args:
            items: List of items to process
            
        Returns:
            List of results in completion order
        """
        if not items:
            return []

        semaphore = asyncio.Semaphore(self.workers)
        results: list[R] = []
        lock = asyncio.Lock()

        async def process(item: T) -> None:
            async with semaphore:
                result = await self.fn(item)
                async with lock:
                    results.append(result)

        await asyncio.gather(*[process(item) for item in items])
        return results

    async def run_with_filter(
        self,
        items: list[T],
        filter_fn: Callable[[R], bool],
    ) -> list[R]:
        """
        Process items and return only results passing the filter.
        
        Args:
            items: List of items to process
            filter_fn: Function to filter results
            
        Returns:
            Filtered list of results
        """
        if not items:
            return []

        semaphore = asyncio.Semaphore(self.workers)
        results: list[R] = []
        lock = asyncio.Lock()

        async def process(item: T) -> None:
            async with semaphore:
                result = await self.fn(item)
                if filter_fn(result):
                    async with lock:
                        results.append(result)

        await asyncio.gather(*[process(item) for item in items])
        return results

    async def for_each(
        self,
        items: list[T],
        callback: Callable[[R], None],
    ) -> None:
        """
        Process items concurrently, calling callback for each result.
        
        Args:
            items: List of items to process
            callback: Function called with each result
        """
        if not items:
            return

        semaphore = asyncio.Semaphore(self.workers)

        async def process(item: T) -> None:
            async with semaphore:
                result = await self.fn(item)
                callback(result)

        await asyncio.gather(*[process(item) for item in items])

    async def run_ordered(self, items: list[T]) -> list[R]:
        """
        Process items concurrently but preserve input order.
        
        Args:
            items: List of items to process
            
        Returns:
            List of results in same order as input
        """
        if not items:
            return []

        semaphore = asyncio.Semaphore(self.workers)

        async def process(item: T) -> R:
            async with semaphore:
                return await self.fn(item)

        return await asyncio.gather(*[process(item) for item in items])


async def parallel_map(
    fn: Callable[[T], Awaitable[R]],
    items: list[T],
    concurrency: int = 10,
) -> list[R]:
    """
    Convenience function for parallel mapping.
    
    Args:
        fn: Async function to apply
        items: Items to process
        concurrency: Max concurrent operations
        
    Returns:
        Results in input order
    """
    pool = WorkerPool(concurrency, fn)
    return await pool.run_ordered(items)


async def parallel_filter(
    fn: Callable[[T], Awaitable[R]],
    items: list[T],
    filter_fn: Callable[[R], bool],
    concurrency: int = 10,
) -> list[R]:
    """
    Convenience function for parallel filtering.
    
    Args:
        fn: Async function to apply
        items: Items to process
        filter_fn: Filter for results
        concurrency: Max concurrent operations
        
    Returns:
        Filtered results
    """
    pool = WorkerPool(concurrency, fn)
    return await pool.run_with_filter(items, filter_fn)
