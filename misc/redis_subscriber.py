import asyncio
import aioredis


async def main():
    sub = await aioredis.create_redis('redis://localhost')
    res = await sub.subscribe('tacacs_accounting:1')
    channel = res[0]

    while (await channel.wait_message()):
        msg = await channel.get_json()
        print("Got Message: {0}".format(msg))

if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
