"""
Author: Justin Turner
Date: May 19, 2026
Description: Enterprise-grade SecOps ChatOps tool for automated incident response.
             Orchestrates SIEM webhooks, structural DLP data classification, 
             threat intelligence enrichment, and stateful firewall mitigation.
"""

import os
import threading
import asyncio
import discord
from discord.ext import commands
from flask import Flask, request, jsonify
import paramiko
import requests
import traceback
from dotenv import load_dotenv

# Load environment boundaries
load_dotenv()


class IncidentResponseView(discord.ui.View):
    """
    Manages interactive UI components for security analysts within Discord.
    Implements least-privilege access control and stateful mitigation loops.
    """
    def __init__(self, attacker_ip: str, target_host: str, bot_instance: commands.Bot):
        super().__init__(timeout=86400)
        self.attacker_ip = attacker_ip
        self.target_host = target_host
        self.bot = bot_instance
        self.pi_ip = os.getenv("PI_IP")
        self.pi_user = os.getenv("PI_USER")
        self.ban_duration = int(os.getenv("BAN_DURATION_SECONDS", 300))

    async def on_error(self, interaction: discord.Interaction, error: Exception, item: discord.ui.Item):
        """CRITICAL DIAGNOSTIC HOOK: Catches silent UI crashes and forces them to print to the console."""
        print(f"\n[CRITICAL UI ERROR] Interaction failed on button '{item.label}':")
        traceback.print_exception(type(error), error, error.__traceback__)
        
        # Attempt to notify the analyst that a backend error occurred
        if not interaction.response.is_done():
            await interaction.response.send_message(f"Backend Execution Error: `{str(error)}`. Check console logs.", ephemeral=True)

    def _is_authorized(self, interaction: discord.Interaction) -> bool:
        """Enforces role-based access control for infrastructure modifications."""
        is_admin = interaction.user.guild_permissions.administrator
        is_owner = interaction.user.id == interaction.guild.owner_id
        return is_admin or is_owner

    def _execute_ssh_command(self, command: str):
        """Synchronous network operation wrapped for thread-safe async execution."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.pi_ip, username=self.pi_user)
        ssh.exec_command(command)
        ssh.close()

    async def _auto_unblock_worker(self, channel_id: int):
        """Asynchronous worker managing the lifecycle of temporary network bans."""
        await asyncio.sleep(self.ban_duration)
        try:
            await asyncio.to_thread(self._execute_ssh_command, f"sudo ufw delete deny from {self.attacker_ip} to any")
            channel = self.bot.get_channel(channel_id)
            if channel:
                await channel.send(
                    f"**Lifecycle Expired:** Temporary containment block lifted for "
                    f"`{self.attacker_ip}` on `{self.target_host}`."
                )
        except Exception as e:
            print(f"[Error] Automated firewall remediation failed: {str(e)}")

    @discord.ui.button(label="Block IP", style=discord.ButtonStyle.danger)
    async def block_ip_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Triggers SSH orchestration to apply a kernel-level firewall block on target endpoint."""
        if not self._is_authorized(interaction):
            await interaction.response.send_message("Access Denied: Administrative privileges required.", ephemeral=True)
            return

        await interaction.response.defer()
        
        await asyncio.to_thread(self._execute_ssh_command, f"sudo ufw deny from {self.attacker_ip} to any")
        
        for child in self.children: 
            child.disabled = True
            
        await interaction.message.edit(
            content=f"**Threat Mitigated:** IP `{self.attacker_ip}` blocked by Analyst {interaction.user.mention}.", 
            view=self
        )
        self.bot.loop.create_task(self._auto_unblock_worker(interaction.channel_id))

    @discord.ui.button(label="Dismiss", style=discord.ButtonStyle.secondary)
    async def false_positive_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Safely dismisses the security alert view across the API gateway."""
        if not self._is_authorized(interaction):
            await interaction.response.send_message("Access Denied: Administrative privileges required.", ephemeral=True)
            return

        for child in self.children: 
            child.disabled = True
            
        await interaction.response.edit_message(
            content=f"**Alert Dismissed:** Triage completed by Analyst {interaction.user.mention}.", 
            view=self
        )


class ArgusBot(commands.Bot):
    """Core ChatOps engine extending commands.Bot to handle gateway streaming and dynamic plugin loading."""
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)
        self.channel_id = int(os.getenv("DISCORD_GENERAL_CHANNEL_ID"))

    async def setup_hook(self):
        """Asynchronous subsystem hook to dynamically mount operational extensions on boot."""
        if not os.path.exists("./cogs"):
            return
            
        for filename in os.listdir("./cogs"):
            if filename.endswith(".py") and not filename.startswith("__"):
                cog_name = f"cogs.{filename[:-3]}"
                try:
                    await self.load_extension(cog_name)
                    print(f"Extension Mounted Successfully: {cog_name}")
                except Exception as e:
                    print(f"[Warning] Handled isolated exception loading extension {cog_name}: {str(e)}")

    async def on_ready(self):
        print(f"Argus Bot Engine is online as: {self.user}")

    async def forward_alert(self, embed: discord.Embed, attacker_ip: str, target_host: str):
        """Ingests structured alert templates, natively instantiates the UI inside the async loop, and dispatches."""
        # ARCHITECTURE FIX: Instantiating the View directly inside the Discord Async Loop 
        # prevents the internal components from breaking when crossing thread boundaries.
        view = IncidentResponseView(attacker_ip=attacker_ip, target_host=target_host, bot_instance=self)
        channel = self.get_channel(self.channel_id)
        if channel: 
            await channel.send(embed=embed, view=view)


class WazuhWebhookServer:
    """Asynchronous Webhook listener acting as an ingestion gateway for SIEM log frames."""
    def __init__(self, bot_instance: ArgusBot):
        self.app = Flask(__name__)
        self.bot = bot_instance
        self.setup_routes()

    def _classify_alert(self, description: str) -> str:
        sensitive_indicators = ['pii', 'confidential', 'ssn', 'database', 'credential', 'secret']
        if any(indicator in description.lower() for indicator in sensitive_indicators):
            return "HIGH SENSITIVITY"
        return "STANDARD"

    def _get_reputation(self, ip_address: str) -> tuple[str, str]:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key or ip_address == "N/A" or ip_address.startswith("127."):
            return "N/A", "Internal/Unknown"
            
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
        headers = {'Accept': 'application/json', 'Key': api_key}
        try:
            response = requests.get(url, headers=headers, timeout=3).json()
            data = response.get('data', {})
            return f"{data.get('abuseConfidenceScore', 0)}%", data.get('countryCode', 'Unknown')
        except Exception:
            return "N/A", "Unknown"

    def setup_routes(self):
        @self.app.route('/webhook', methods=['POST'])
        def webhook():
            payload = request.json
            alert = payload.get('all_fields', payload)
            rule = alert.get('rule', {})
            
            rule_id = rule.get('id', 'Unknown')
            description = rule.get('description', 'No Details Provided')
            src_ip = alert.get('data', {}).get('srcip', 'N/A')
            agent_name = alert.get('agent', {}).get('name', 'Unknown Engine')
            
            sensitivity = self._classify_alert(description)
            score, country = self._get_reputation(src_ip)

            embed = discord.Embed(
                title=f"ALERT - SIGNATURE MATCH ID {rule_id}", 
                description=description, 
                color=0xff0000 if sensitivity == "HIGH SENSITIVITY" else 0xffa500
            )
            embed.add_field(name="Data Classification", value=f"`{sensitivity}`", inline=True)
            embed.add_field(name="Target Endpoint", value=f"`{agent_name}`", inline=True)
            embed.add_field(name="Source Attacker IP", value=f"`{src_ip}`", inline=True)
            embed.add_field(name="Threat Intel Score", value=f"`{score}`", inline=True)
            embed.add_field(name="Country Origin", value=f"`{country}`", inline=True)
            embed.add_field(name="\u200b", value="\u200b", inline=True)
            embed.set_footer(text="Argus Automated Response Pipeline - DLP Classification Enabled")
            
            # Pass primitive data strings into the threadsafe queue, let Discord handle the complex View generation natively.
            asyncio.run_coroutine_threadsafe(
                self.bot.forward_alert(embed, attacker_ip=src_ip, target_host=agent_name), 
                self.bot.loop
            )
            
            return jsonify({"status": "processed"}), 200

    def start(self):
        threading.Thread(
            target=lambda: self.app.run(host='0.0.0.0', port=5000, use_reloader=False), 
            daemon=True
        ).start()


if __name__ == "__main__":
    bot = ArgusBot()
    WazuhWebhookServer(bot_instance=bot).start()
    bot.run(os.getenv("DISCORD_BOT_TOKEN"))