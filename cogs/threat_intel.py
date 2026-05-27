"""
Author: Justin Turner
Date: May 18, 2026
Description: Standalone Threat Intelligence extension that monitors public OSINT 
             and vulnerability research RSS feeds, distributing daily rollups.
             Utilizes timezone-aware native loops and epoch normalization.
"""

import os
import asyncio
import calendar
import zoneinfo
from datetime import datetime, time as dtime, timedelta, timezone
import discord
from discord.ext import commands, tasks
import feedparser

# Define explicit scheduling constraints at the module layer
CHICAGO_TZ = zoneinfo.ZoneInfo("America/Chicago")
DAILY_POST_TIME = dtime(hour=6, minute=0, tzinfo=CHICAGO_TZ)

class ThreatIntel(commands.Cog):
    """Threat Intelligence engine for aggregating structural security feeds."""
    
    def __init__(self, bot):
        self.bot = bot
        
        # Pull configuration parameters from environment variables
        self.channel_id = int(os.getenv("DISCORD_THREAT_INTEL_CHANNEL_ID", 0))
        self.user_id = int(os.getenv("PWNEDBYJT_DISCORD_USER_ID", 0))
        
        self.feeds = {
            "Exploit-DB": "https://www.exploit-db.com/rss.xml",
            "Zero Day Initiative": "https://www.zerodayinitiative.com/rss/published/",
            "PortSwigger Research": "https://portswigger.net/research/rss",
            "CISA Alerts": "https://www.cisa.gov/uscert/ncas/alerts.xml",
            "SANS Internet Storm Center": "https://isc.sans.edu/rssfeed_full.xml",
            "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
            "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
            "Krebs on Security": "https://krebsonsecurity.com/feed/"
        }
        
        # Instantiate background loop scheduler
        self.daily_loop_task.start()

    @commands.Cog.listener()
    async def on_ready(self):
        print(f"Extension Loaded: cogs.threat_intel module active.")

    async def fetch_and_post(self):
        """Scrapes upstream RSS architectures and forwards recent indicators to Discord."""
        channel = self.bot.get_channel(self.channel_id)
        if not channel:
            print(f"[Error] Threat Intel channel with ID {self.channel_id} could not be resolved.")
            return

        await channel.send(f"<@{self.user_id}> Starting daily threat intelligence extraction routine...")

        # Establish a timezone-aware 24-hour lookback window in UTC
        cutoff = datetime.now(timezone.utc) - timedelta(days=1)
        count = 0

        for name, url in self.feeds.items():
            try:
                # Offload blocking network parsing to a separate thread executor
                feed = await self.bot.loop.run_in_executor(None, feedparser.parse, url)
                for entry in feed.entries:
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        # Correctly interpret the timetuple as UTC epoch seconds
                        epoch = calendar.timegm(entry.published_parsed)
                        pub_date = datetime.fromtimestamp(epoch, tz=timezone.utc)

                        if pub_date > cutoff:
                            embed = discord.Embed(
                                title=entry.title, 
                                url=entry.link, 
                                color=discord.Color.dark_red()
                            )
                            embed.set_footer(text=f"Source: {name} | Automated OSINT Ingestion")
                            await channel.send(embed=embed)
                            count += 1
                            await asyncio.sleep(1.5)  # Enforce spacing to honor API rate limits
            except Exception as e:
                print(f"[Error] Failed to fetch feed '{name}': {str(e)}")

        await channel.send(f"<@{self.user_id}> Threat intel ingest complete. Distributed {count} recent publications.")

    @tasks.loop(time=DAILY_POST_TIME)
    async def daily_loop_task(self):
        """Native scheduler execution block triggered exactly once a day at the designated time."""
        print(f"[System] Initiating scheduled daily Threat Intel routine.")
        await self.fetch_and_post()

    @daily_loop_task.before_loop
    async def before_daily_loop_task(self):
        """Hold task loop instantiation until the core bot connection stabilizes."""
        await self.bot.wait_until_ready()

    @commands.command(name="intel")
    async def intel(self, ctx):
        """Manual override context trigger for interactive analytics debugging."""
        if ctx.author.id == self.user_id:
            await self.fetch_and_post()
        else:
            await ctx.send("Access Denied: Insufficient analytical privileges.", delete_after=10)

    def cog_unload(self):
        """Cleanly terminate task routines upon module hot-unloads."""
        self.daily_loop_task.cancel()

async def setup(bot):
    """Hook standard required by discord.py extension loading mechanics."""
    await bot.add_cog(ThreatIntel(bot))