module.exports = {
  apps: [
    {
      name: "argus",
      script: "./argus.py",
      interpreter: "python3",
      watch: false,
      env: {
        DISCORD_BOT_TOKEN: "",
        DISCORD_GENERAL_CHANNEL_ID: "",
        DISCORD_THREAT_INTEL_CHANNEL_ID: "",
        PWNEDBYJT_DISCORD_USER_ID: "",
        PI_IP: "",
        PI_USER: "",
        ABUSEIPDB_API_KEY: "",
        BAN_DURATION_SECONDS: "300"
      }
    }
  ]
};
