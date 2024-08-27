from pb_fthreads import FThreadPool, sleep_until_ms
# from pybricks.tools import wait


async def main(thread_pool, thread_id):
    print("[MainThread] started...")
    print("[MainThread] assigned to thread #{}".format(thread_id))

    counter = 0
    while counter < 10:
        print("[MainThread] + counter {}".format(counter))
        thread_pool.spawn(child, counter, counter)
        print("[MainThread] + spawned a child thread")
        counter += 1
        await sleep_until_ms(1000)

    print("[MainThread] ended...")


async def child(id, counter, thread_pool, thread_id):
    print("[ChildThread #{}] started...".format(id))
    print("[ChildThread #{}] assigned to thread #{}".format(id, thread_id))
    local_counter = counter
    while local_counter > 0:
        print("[ChildThread #{}] + counter {}".format(id, local_counter))
        local_counter -= 1
        await sleep_until_ms(1000)
    print("[ChildThread #{}] ended...".format(id))


thread_pool = FThreadPool(3)
thread_pool.spawn(main)
thread_pool.run()
