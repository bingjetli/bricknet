# PyBricks FauxThreads

This is an importable module for [PyBricks](https://pybricks.com) that simulates the behavior of [Thread Pools](https://en.wikipedia.org/wiki/Thread_pool) using the native async/await coroutines.

&nbsp;

# The limitations of concurrency in PyBricks

At the time of writing, concurrency support in PyBricks is limited to a basic implementation of Python [coroutines](https://docs.python.org/3/glossary.html#term-coroutine) and the `multitask()` and `run_task()` functions.

`multitask()` works similarly to [asyncio.gather()](https://docs.python.org/3/library/asyncio-task.html#asyncio.gather) where a list of `coroutines` can be passed into the function arguments, where they will be executed concurrently.

Likewise, `run_task()` works similarly to [asyncio.run()](https://docs.python.org/3/library/asyncio-runner.html#asyncio.run) where a `coroutine` can be passed into the function as an argument, where it will execute while blocking the main thread.

Therefore `coroutines` need to be defined at compile-time and they cannot be dynamically created at run-time.

&nbsp;

# How this module works

This module simulates the behavior of thread pools by allowing the user to define a number of concurrent `coroutines` at compile-time.

Then, "threads" can be "spawned" at run-time to execute actions concurrently using one of the available `coroutines` defined in the pool in the previous step.

The `coroutines` will run all the "threads" assigned to it until all actions associated with each "thread" is finished. When no active "threads" exist, the program will terminate.

&nbsp;

# Usage

1. Ensure that PyBricks is installed on your LEGO SPIKE Hub.

2. Upload `pb_fthreads.py` to your LEGO SPIKE Hub using [PyBricks Code](https://code.pybricks.com/).

3. Create a new script, and import the `FThreadPool` class from `pb_fthreads.py`.

4. Define your threads using the `async def FUNCTION_NAME(thread_pool, thread_id)` function definition syntax.

5. Instantiate the `FThreadPool` class with the specified number of worker threads inside the pool.

6. Spawn at least 1 thread (typically the main thread) using the `.spawn(FUNCTION_NAME, ARGS, KWARGS)` method.

7. Start the thread pool executor using the `.run()` method.

&nbsp;

# Example

```python
from pb_fthreads import FThreadPool

async def main(thread_pool, thread_id):
  ## Do work in the main thread...

  ## Spawn a background thread at some point...
  thread_pool.spawn(background)


async def background(thread_pool, thread_id):
  ## Do work in the background thread...


if __name__ == "__main__":
  ## Initialize the thread pool with 4 worker threads.
  thread_pool = FThreadPool(4)

  ## Spawn at least 1 thread (the main thread).
  thread_pool.spawn(main)

  ## Start the thread pool executor. This will now block until all the threads are finished.
  thread_pool.run()

```

For a more detailed example, see the basic example in [basic_example.py](./basic_example.py)

&nbsp;

# Documentation

## `FThreadPool(number_of_threads)`

Instantiates the FauxThread pool with the specified number of worker threads.

## `.spawn(coroutine, *args, **kwargs)`

Adds the specified `coroutine` to the queue of "threads" to be spawned. When a worker thread is available, it will be assigned to it and run the `coroutine`.

The `coroutine` can receive positional arguments as well as keyword arguments which will be passed into the `coroutine` when a worker thread is ready to execute it.

## `.run()`

Starts the thread pool executor and blocks the main thread until all the worker threads have finished executing their coroutines.

## Defining `coroutines` for the worker threads

These must be defined with the following syntax:

```python
async def FUNCTION_NAME(*ARGS, **KWARGS, thread_pool, thread_id):
  ## Coroutine definition...

```

Both `thread_pool` and `thread_id` **MUST** be included in the function definition.

`thread_pool` contains a reference to the thread pool executor, which can be used to dynamically spawn more threads inside the `coroutine` at run-time.

`thread_id` contains the id of the worker thread that is currently executing the `coroutine`.

Optional positional parameters and keyword parameters can be defined as well, typically before the required `thread_pool` and `thread_id` kwargs.
