import asyncio

async def main():
    loop = asyncio.get_running_loop()
    future  = loop.create_future()

    print(type(future))

asyncio.run(main())