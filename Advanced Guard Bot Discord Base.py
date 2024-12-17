import discord
from discord.ext import commands
from collections import defaultdict, deque
import asyncio
import datetime
import re
import emoji
import aiohttp
import os
import logging
from dotenv import load_dotenv
import unicodedata
import hashlib
import io
from PIL import Image
import json
import random
from fuzzywuzzy import fuzz

# Import Configuration
from config import bot_config

# --- Setup ---

logging.basicConfig(
    level=getattr(logging, bot_config.LOGGING_LEVEL), 
    format=bot_config.LOGGING_FORMAT
)

# --- Constants ---

SLOW_MODE_DELAY = bot_config.Safety.SLOW_MODE_DELAY
DUPLICATE_RESET_TIME = bot_config.Moderation.DUPLICATE_RESET_TIME
DUPLICATE_MSG_THRESHOLD = bot_config.Moderation.DUPLICATE_MSG_THRESHOLD
CAPITALIZATION_THRESHOLD = bot_config.Moderation.CAPITALIZATION_THRESHOLD
SPAM_TIME = bot_config.Moderation.SPAM_TIME
SPAM_THRESHOLD = bot_config.Moderation.SPAM_THRESHOLD
RAID_THRESHOLD = bot_config.Moderation.RAID_THRESHOLD
RAID_TIME = bot_config.Moderation.RAID_TIME
EMOJI_THRESHOLD = bot_config.Moderation.EMOJI_THRESHOLD
WARNING_LIMIT = bot_config.Moderation.WARNING_LIMIT
MUTE_DURATION_30S = bot_config.Moderation.MUTE_DURATION_30S
MUTE_DURATION_5M = bot_config.Moderation.MUTE_DURATION_5M
IMAGE_DUPLICATE_TIME_WINDOW = bot_config.Safety.IMAGE_DUPLICATE_TIME_WINDOW

# --- Initialize Bot ---

intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.presences = True
bot = commands.Bot(command_prefix=bot_config.COMMAND_PREFIX, intents=intents)

# --- Tracking Dictionaries ---

user_messages = defaultdict(lambda: deque(maxlen=SPAM_THRESHOLD))
message_history = defaultdict(lambda: deque(maxlen=DUPLICATE_MSG_THRESHOLD))
user_image_hashes = defaultdict(list)
member_join_times = defaultdict(lambda: deque(maxlen=RAID_THRESHOLD))
suspicious_accounts = set()
spam_warnings = defaultdict(int)

# Global message tracking deque
user_message_deque = deque(maxlen=bot_config.Moderation.FLOOD_THRESHOLD)

# --- Data Storage ---

user_data_file = bot_config.FilePaths.USER_DATA_FILE

# --- Helper Functions ---

def normalize_text(text):
    return re.sub(r'[^\w\s]', '', text).lower()

def is_similar(existing_message, new_message, threshold=90):
    return fuzz.ratio(normalize_text(existing_message), normalize_text(new_message)) >= threshold

def load_bot_status_messages(file_path='bot_status_messages.txt'):
    """
    Load bot status messages from a text file, filtering out comments and empty lines
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Read lines, strip whitespace, remove comments and empty lines
            status_messages = [
                line.strip() 
                for line in f 
                if line.strip() and not line.strip().startswith('#')
            ]
        
        # Shuffle messages to provide variety
        random.shuffle(status_messages)
        
        return status_messages
    except FileNotFoundError:
        logging.error(f"Bot status messages file not found: {file_path}")
        # Fallback to default messages if file is not found
        return [
            "Güvenlik her şeyden önce!",
            "Sunucuyu korumak için buradayım!",
            "Güvenlik sistemleri aktif!",
            "Her an tetikte!",
            "Tehlikelere geçit yok!"
        ]
    except Exception as e:
        logging.error(f"Error loading bot status messages: {e}")
        return []

BOT_STATUS_MESSAGES = load_bot_status_messages()

async def update_status():
    global BOT_STATUS_MESSAGES  
    await bot.wait_until_ready()
    
    while not bot.is_closed():
        try:
            # If no messages, reset the list
            if not BOT_STATUS_MESSAGES:
                BOT_STATUS_MESSAGES = load_bot_status_messages()
            
            # Choose a random status message
            if BOT_STATUS_MESSAGES:
                status_message = BOT_STATUS_MESSAGES.pop(0)
                
                # Set bot's activity
                await bot.change_presence(
                    activity=discord.Activity(
                        type=discord.ActivityType.watching, 
                        name=status_message
                    )
                )
            
            # Wait before changing status again (randomize interval)
            await asyncio.sleep(random.randint(900, 1800))  # 15-30 minutes
        
        except Exception as e:
            logging.error(f"Error updating bot status: {e}")
            await asyncio.sleep(600)  # Wait 10 minutes if error occurs

def contains_excessive_emojis(text, threshold=EMOJI_THRESHOLD):
    return emoji.emoji_count(text) > threshold

def count_mentions(message):
    return len(message.mentions)

def is_link(message_content):
    return re.search(r'(https?://\S+)', message_content)

async def analyze_link_safety(url):
    async with aiohttp.ClientSession() as session:
        headers = {'x-apikey': bot_config.VIRUSTOTAL_API_KEY}
        async with session.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url}) as response:
            if response.status == 200:
                json_response = await response.json()
                scan_id = json_response.get('data', {}).get('id')
                if scan_id:
                    async with session.get(f'https://www.virustotal.com/api/v3/analyses/{scan_id}', headers=headers) as result_response:
                        if result_response.status == 200:
                            result = await result_response.json()
                            last_analysis_stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                            return last_analysis_stats.get('malicious', 0) == 0
            return False

async def analyze_file_safety(file_url):
    async with aiohttp.ClientSession() as session:
        headers = {'x-apikey': bot_config.VIRUSTOTAL_API_KEY}
        try:
            async with session.get(file_url) as file_response:
                if file_response.status != 200:
                    return False
                file_content = await file_response.read()
                data = aiohttp.FormData()
                data.add_field('file', file_content, filename='file', content_type='application/octet-stream')
                upload_url = 'https://www.virustotal.com/api/v3/files'
                async with session.post(upload_url, headers=headers, data=data) as response:
                    if response.status == 200:
                        json_response = await response.json()
                        file_id = json_response.get('data', {}).get('id')
                        if file_id:
                            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
                            await asyncio.sleep(30)  # Wait for analysis to complete
                            async with session.get(analysis_url, headers=headers) as result_response:
                                if result_response.status == 200:
                                    result = await result_response.json()
                                    last_analysis_stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                                    return last_analysis_stats.get('malicious', 0) == 0
        except Exception as e:
            logging.error(f"File analysis failed: {e}")
        return False

def is_duplicate_image(user_id, image_hash, current_time):
    return any(hash == image_hash and (current_time - timestamp).total_seconds() <= IMAGE_DUPLICATE_TIME_WINDOW
                for hash, timestamp in user_image_hashes[user_id])

def load_user_data(file_path='user_data.json'):
    """
    Load user data from JSON file with robust encoding handling
    """
    try:
        # Try UTF-8 encoding first (recommended)
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Create an empty file if not found
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump({}, f)
        return {}
    except UnicodeDecodeError:
        # Fallback to different encodings
        encodings_to_try = ['cp1254', 'latin1', 'iso-8859-9']
        for encoding in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    data = json.load(f)
                
                # Rewrite the file in UTF-8 to prevent future encoding issues
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=4)
                
                return data
            except Exception:
                continue
        
        # If all encoding attempts fail, return an empty dictionary
        print(f"Warning: Could not load user data from {file_path}. Creating a new file.")
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump({}, f)
        return {}

def save_user_data(data, file_path='user_data.json'):
    """
    Save user data to JSON file with proper serialization and UTF-8 encoding
    """
    def serialize_discord_objects(obj):
        """
        Custom JSON serializer for Discord objects
        """
        if isinstance(obj, discord.Role):
            return {'role_id': obj.id, 'role_name': obj.name}
        elif isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return str(obj)

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(
                data, 
                f, 
                indent=4, 
                ensure_ascii=False, 
                default=serialize_discord_objects
            )
    except Exception as e:
        print(f"Error saving user data: {e}")

async def collect_user_data(member, guild, event_type, event_data):
    """
    Collect and save user data across different event types
    """
    # Determine the file path for user data
    user_data_file = bot_config.FilePaths.USER_DATA_FILE if hasattr(bot_config.FilePaths, 'USER_DATA_FILE') else 'user_data.json'
    
    # Load existing user data
    user_data = load_user_data(user_data_file)
    
    # Convert member ID to string for JSON compatibility
    user_id = str(member.id)
    
    # Initialize user data if not exists
    if user_id not in user_data:
        user_data[user_id] = {
            'username': member.name,
            'join_date': member.joined_at.isoformat() if member.joined_at else None,
            'events': []
        }
    
    # Add current event to user's event history
    event_entry = {
        'type': event_type,
        'timestamp': datetime.datetime.now().isoformat(),
        'details': str(event_data)[:500]  # Limit details to prevent excessive storage
    }
    
    # Append event, keeping only the last 50 events to prevent data bloat
    if 'events' not in user_data[user_id]:
        user_data[user_id]['events'] = []
    user_data[user_id]['events'].append(event_entry)
    user_data[user_id]['events'] = user_data[user_id]['events'][-50:]
    
    # Use asyncio to run save_user_data in a separate thread to avoid blocking
    await asyncio.to_thread(save_user_data, user_data, user_data_file)

def get_suspicious_actions(user_id):
    return []  # Return empty list instead of anomaly detection

# --- Profanity and Content Filtering ---
def load_profanity_list():
    with open('profanity_list.txt', 'r', encoding='utf-8') as f:
        return set(word.strip().lower() for word in f.readlines())

profanity_list = load_profanity_list()

def contains_profanity(text):
    """
    Check if the text contains any profane words.
    Checks for whole words and partial matches to catch variations.
    """
    text = text.lower()
    words = text.split()
    
    # Check for exact and partial matches
    for word in words:
        for profanity in profanity_list:
            if profanity in word or word in profanity:
                return True
    return False

def advanced_profanity_check(message_content):
    """
    Advanced profanity detection using Fuzzywuzzy for similarity checking
    """
    message_words = message_content.lower().split()
    for word in message_words:
        for profanity in profanity_list:
            # Lower similarity threshold to catch more variations
            if fuzz.ratio(word, profanity) > 70 or \
               fuzz.partial_ratio(word, profanity) > 80:
                return True
    return False

# --- Advanced Security Features ---
class SecurityMonitor:
    def __init__(self):
        # Initialize protection tracking with configuration-driven defaults
        self.role_protection = defaultdict(dict)
        self.channel_protection = defaultdict(dict)
        self.server_protection = defaultdict(dict)
        self.member_protection = defaultdict(dict)
        
        # Protection tracking with limits from configuration
        self.ban_protection = defaultdict(set)
        self.kick_protection = defaultdict(dict)
        self.bot_protection = defaultdict(set)
        
        # Tracking unauthorized actions
        self._unauthorized_actions = defaultdict(list)
        
        # Initialize with default protection levels from config
        self.default_protection_setup()

    def default_protection_setup(self):
        """
        Set up default protection levels based on configuration
        """
        # Default role protection
        self.default_role_protection = bot_config.SecurityProtection.DEFAULT_ROLE_PROTECTION
        
        # Default channel protection
        self.default_channel_protection = bot_config.SecurityProtection.DEFAULT_CHANNEL_PROTECTION
        
        # Default server update protection
        self.default_server_update_protection = bot_config.SecurityProtection.DEFAULT_SERVER_UPDATE_PROTECTION
        
        # Default member update protection
        self.default_member_update_protection = bot_config.SecurityProtection.DEFAULT_MEMBER_UPDATE_PROTECTION

    def validate_protection_level(self, protection_type, level):
        """
        Validate protection level against configuration
        """
        valid_levels = {
            'role': bot_config.SecurityProtection.ROLE_PROTECTION_LEVELS,
            'channel': bot_config.SecurityProtection.CHANNEL_PROTECTION_LEVELS,
            'server': bot_config.SecurityProtection.SERVER_UPDATE_PROTECTION_LEVELS,
            'member': bot_config.SecurityProtection.MEMBER_UPDATE_PROTECTION_LEVELS
        }
        
        if level not in valid_levels.get(protection_type, {}):
            # Default to basic protection if invalid level specified
            return 'basic'
        return level

    def enable_role_protection(self, guild_id, role_id=None, protection_level=None):
        """
        Enable role protection with configuration validation
        """
        # Use default if no protection level specified
        if protection_level is None:
            protection_level = self.default_role_protection
        
        # Validate protection level
        protection_level = self.validate_protection_level('role', protection_level)
        
        # Check protection limits
        if role_id:
            # Limit number of protected roles per guild
            current_protected_roles = sum(1 for r in self.role_protection[guild_id].keys() if r != 'default')
            if current_protected_roles >= bot_config.SecurityProtection.MAX_PROTECTED_ROLES_PER_GUILD:
                logging.warning(f"Maximum protected roles limit reached for guild {guild_id}")
                return False
            
            self.role_protection[guild_id][role_id] = protection_level
        else:
            # Set default guild-wide protection
            self.role_protection[guild_id]['default'] = protection_level
        
        return True

    def enable_channel_protection(self, guild_id, channel_id=None, protection_level=None):
        """
        Enable channel protection with configuration validation
        """
        # Use default if no protection level specified
        if protection_level is None:
            protection_level = self.default_channel_protection
        
        # Validate protection level
        protection_level = self.validate_protection_level('channel', protection_level)
        
        # Check protection limits
        if channel_id:
            # Limit number of protected channels per guild
            current_protected_channels = sum(1 for c in self.channel_protection[guild_id].keys() if c != 'default')
            if current_protected_channels >= bot_config.SecurityProtection.MAX_PROTECTED_CHANNELS_PER_GUILD:
                logging.warning(f"Maximum protected channels limit reached for guild {guild_id}")
                return False
            
            self.channel_protection[guild_id][channel_id] = protection_level
        else:
            # Set default guild-wide protection
            self.channel_protection[guild_id]['default'] = protection_level
        
        return True

    def enable_server_protection(self, guild_id, protection_level=None):
        """
        Enable server update protection with configuration validation
        """
        # Use default if no protection level specified
        if protection_level is None:
            protection_level = self.default_server_update_protection
        
        # Validate protection level
        protection_level = self.validate_protection_level('server', protection_level)
        
        # Set server protection
        self.server_protection[guild_id] = protection_level
        return True

    def enable_member_protection(self, guild_id, protection_level=None):
        """
        Enable member update protection with configuration validation
        """
        # Use default if no protection level specified
        if protection_level is None:
            protection_level = self.default_member_update_protection
        
        # Validate protection level
        protection_level = self.validate_protection_level('member', protection_level)
        
        # Set member protection
        self.member_protection[guild_id] = protection_level
        return True

    def protect_against_ban(self, guild_id, user_id):
        """
        Protect a user from being banned with configuration limits
        """
        # Check protection limits
        if len(self.ban_protection[guild_id]) >= bot_config.SecurityProtection.MAX_PROTECTED_USERS_FROM_BAN:
            logging.warning(f"Maximum protected users from ban limit reached for guild {guild_id}")
            return False
        
        self.ban_protection[guild_id].add(user_id)
        return True

    def protect_against_kick(self, guild_id, user_id, reason=None):
        """
        Protect a user from being kicked with configuration limits
        """
        # Check protection limits
        if len(self.kick_protection[guild_id]) >= bot_config.SecurityProtection.MAX_PROTECTED_USERS_FROM_KICK:
            logging.warning(f"Maximum protected users from kick limit reached for guild {guild_id}")
            return False
        
        self.kick_protection[guild_id][user_id] = {
            'protected': True,
            'reason': reason or 'General Protection'
        }
        return True

    def protect_bot(self, guild_id, bot_id):
        """
        Protect a specific bot with configuration validation
        """
        # Check protection limits
        if len(self.bot_protection[guild_id]) >= bot_config.SecurityProtection.MAX_PROTECTED_BOTS_PER_GUILD:
            logging.warning(f"Maximum protected bots limit reached for guild {guild_id}")
            return False
        
        # Add bot to protected list
        self.bot_protection[guild_id].add(bot_id)
        return True

    def check_role_protection(self, guild_id, role_id, action_type):
        """
        Check if a role modification is allowed based on protection settings
        """
        guild_protection = self.role_protection.get(guild_id, {})
        role_protection = guild_protection.get(role_id, guild_protection.get('default', 'none'))
        
        # Convert protection level to numeric for comparison
        protection_levels = bot_config.SecurityProtection.ROLE_PROTECTION_LEVELS
        
        if protection_levels.get(role_protection, 0) == protection_levels['strict']:
            return False
        elif protection_levels.get(role_protection, 0) == protection_levels['basic'] and action_type in ['delete', 'update']:
            return False
        return True

    def check_channel_protection(self, guild_id, channel_id, action_type):
        """
        Check if a channel modification is allowed based on protection settings
        """
        guild_protection = self.channel_protection.get(guild_id, {})
        channel_protection = guild_protection.get(channel_id, guild_protection.get('default', 'none'))
        
        # Convert protection level to numeric for comparison
        protection_levels = bot_config.SecurityProtection.CHANNEL_PROTECTION_LEVELS
        
        if protection_levels.get(channel_protection, 0) == protection_levels['strict']:
            return False
        elif protection_levels.get(channel_protection, 0) == protection_levels['basic'] and action_type in ['delete', 'update']:
            return False
        return True

    def check_server_protection(self, guild_id):
        """
        Check if server updates are allowed
        """
        protection_levels = bot_config.SecurityProtection.SERVER_UPDATE_PROTECTION_LEVELS
        protection_level = self.server_protection.get(guild_id, 'none')
        
        return protection_levels.get(protection_level, 0) == protection_levels['none']

    def check_member_protection(self, guild_id):
        """
        Check if member updates are allowed
        """
        protection_levels = bot_config.SecurityProtection.MEMBER_UPDATE_PROTECTION_LEVELS
        protection_level = self.member_protection.get(guild_id, 'none')
        
        return protection_levels.get(protection_level, 0) == protection_levels['none']

    def is_ban_protected(self, guild_id, user_id):
        """
        Check if a user is protected from being banned
        """
        return user_id in self.ban_protection.get(guild_id, set())

    def is_kick_protected(self, guild_id, user_id):
        """
        Check if a user is protected from being kicked
        """
        return (self.kick_protection.get(guild_id, {}).get(user_id, {}).get('protected', False))

    def is_bot_protected(self, guild_id, bot_id):
        """
        Check if a bot is protected from unauthorized actions
        """
        return bot_id in self.bot_protection.get(guild_id, set())

    def log_unauthorized_action(self, guild_id, action_type, details):
        """
        Log unauthorized actions with configuration-based limits
        """
        # Check if logging is enabled in configuration
        if not bot_config.SecurityProtection.LOG_UNAUTHORIZED_ACTIONS:
            return
        
        # Limit number of unauthorized action logs
        if len(self._unauthorized_actions[guild_id]) >= bot_config.SecurityProtection.MAX_UNAUTHORIZED_ACTION_LOGS:
            # Remove oldest log if limit is reached
            self._unauthorized_actions[guild_id].pop(0)
        
        # Log the unauthorized action
        self._unauthorized_actions[guild_id].append({
            'timestamp': datetime.datetime.now(),
            'action_type': action_type,
            'details': details
        })
        
        # Optional: Send notification to security alerts channel
        if bot_config.SecurityProtection.NOTIFY_ON_PROTECTION_VIOLATION:
            self.notify_protection_violation(guild_id, action_type, details)

    def notify_protection_violation(self, guild_id, action_type, details):
        """
        Send notification about protection violation to configured channel
        """
        # This method would be implemented to send a message to the security alerts channel
        # You would need to pass the bot instance or use a bot method to send the message
        pass

    def is_trusted(self, user_id):
        """
        Check if a user is considered trusted based on predefined criteria.
        
        Args:
            user_id (int): The ID of the user to check.
        
        Returns:
            bool: True if the user is trusted, False otherwise.
        """
        # You can customize this method to define your trusted user criteria
        # For example, checking against a list of admin/moderator user IDs
        trusted_users = bot_config.TRUSTED_USERS if hasattr(bot_config, 'TRUSTED_USERS') else []
        return user_id in trusted_users

    async def log_action(self, guild, action_type, user, reason):
        """
        Log moderation actions to the configured log channel
        """
        log_channel_id = bot_config.Security.LOG_CHANNEL
        log_channel = None

        # Try to find channel by ID first
        try:
            log_channel = guild.get_channel(int(log_channel_id))
        except (ValueError, TypeError):
            # If not an ID, try to find channel by name
            log_channel = discord.utils.get(guild.text_channels, name=log_channel_id)

        # If no channel found, try to create one
        if not log_channel:
            try:
                log_channel = await guild.create_text_channel('security-logs')
                print(f"Created new security logs channel in {guild.name}")
            except discord.Forbidden:
                print(f"Failed to create security logs channel in {guild.name}")
                return
        
        # Create and send embed
        try:
            embed = discord.Embed(
                title=f"Moderation Action: {action_type}",
                color=discord.Color.red(),
                timestamp=datetime.datetime.now()
            )
            embed.add_field(name="User", value=f"{user.name}#{user.discriminator} ({user.id})", inline=False)
            embed.add_field(name="Reason", value=reason, inline=False)
            embed.set_footer(text=f"Action taken by {guild.me.name}")
            
            await log_channel.send(embed=embed)
        except Exception as e:
            print(f"Failed to send log message: {e}")

# Initialize security monitor with configuration-driven defaults
security_monitor = SecurityMonitor()

# Modify existing event handlers to use these new protection methods
@bot.event
async def on_guild_role_delete(role):
    if not security_monitor.check_role_protection(role.guild.id, role.id, 'delete'):
        # Prevent role deletion or take corrective action
        security_monitor.log_unauthorized_action(role.guild.id, 'role_delete', {'role_name': role.name})
        return False  # Prevent the deletion

@bot.event
async def on_guild_channel_delete(channel):
    if not security_monitor.check_channel_protection(channel.guild.id, channel.id, 'delete'):
        # Prevent channel deletion or take corrective action
        security_monitor.log_unauthorized_action(channel.guild.id, 'channel_delete', {'channel_name': channel.name})
        return False  # Prevent the deletion

@bot.event
async def on_guild_update(before, after):
    if not security_monitor.check_server_protection(before.id):
        # Prevent server updates or take corrective action
        security_monitor.log_unauthorized_action(before.id, 'server_update', {
            'before_name': before.name,
            'after_name': after.name
        })
        return False  # Prevent the update

@bot.event
async def on_member_update(before, after):
    if not security_monitor.check_member_protection(before.guild.id):
        # Prevent member updates or take corrective action
        security_monitor.log_unauthorized_action(before.guild.id, 'member_update', {
            'user_id': before.id,
            'changes': str(before) + ' -> ' + str(after)
        })
        return False  # Prevent the update

@bot.event
async def on_member_ban(guild, user):
    if security_monitor.is_ban_protected(guild.id, user.id):
        # Prevent banning a protected user
        security_monitor.log_unauthorized_action(guild.id, 'ban_attempt', {
            'user_id': user.id,
            'user_name': user.name
        })
        return False  # Prevent the ban

@bot.event
async def on_member_kick(guild, user):
    if security_monitor.is_kick_protected(guild.id, user.id):
        # Prevent kicking a protected user
        security_monitor.log_unauthorized_action(guild.id, 'kick_attempt', {
            'user_id': user.id,
            'user_name': user.name
        })
        return False  # Prevent the kick

# --- Server Configuration Backup and Restore ---
class ServerConfigManager:
    def __init__(self, config_file='server_config_backup.json'):
        self.config_file = config_file
        self.current_config = {}
        self.load_config()
    
    def load_config(self):
        try:
            with open(self.config_file, 'r') as f:
                self.current_config = json.load(f)
        except FileNotFoundError:
            self.current_config = {}
    
    def save_config(self, guild):
        """Sunucunun mevcut ayarlarını yedekle"""
        guild_config = {
            'name': guild.name,
            'icon': str(guild.icon.url) if guild.icon else None,
            'banner': str(guild.banner.url) if guild.banner else None,
            'verification_level': guild.verification_level.value,
            'default_notifications': guild.default_notifications.value,
            'explicit_content_filter': guild.explicit_content_filter.value,
            'roles': [
                {
                    'id': role.id,
                    'name': role.name,
                    'color': role.color.value,
                    'permissions': role.permissions.value,
                    'mentionable': role.mentionable,
                    'hoist': role.hoist
                } for role in guild.roles
            ],
            'channels': [
                {
                    'id': channel.id,
                    'name': channel.name,
                    'type': str(channel.type),
                    'category': channel.category.id if channel.category else None,
                    'position': channel.position,
                    'overwrites': {
                        str(target.id): {
                            'allow': overwrite.pair()[0].value,
                            'deny': overwrite.pair()[1].value
                        } for target, overwrite in channel.overwrites.items()
                    }
                } for channel in guild.channels
            ]
        }
        
        self.current_config[str(guild.id)] = guild_config
        
        with open(self.config_file, 'w') as f:
            json.dump(self.current_config, f, indent=4)
        
        # Performans optimizasyonu için önbelleğe al
        performance_optimizer.cache['guild_configs'][guild.id] = guild_config
        
    async def restore_config(self, guild):
        """Sunucunun önceki ayarlarını geri yükle"""
        guild_config = self.current_config.get(str(guild.id))
        if not guild_config:
            logging.warning(f"No backup configuration found for guild {guild.name}")
            return False
        
        try:
            # Sunucu adını geri yükle
            await guild.edit(name=guild_config['name'])
            
            # Roller için geri yükleme
            for role_data in guild_config['roles']:
                try:
                    role = discord.utils.get(guild.roles, id=role_data['id'])
                    if role:
                        await role.edit(
                            name=role_data['name'],
                            color=discord.Color(role_data['color']),
                            permissions=discord.Permissions(role_data['permissions']),
                            mentionable=role_data['mentionable'],
                            hoist=role_data['hoist']
                        )
                except Exception as e:
                    logging.error(f"Error restoring role {role_data['name']}: {e}")
            
            # Kanallar için geri yükleme
            for channel_data in guild_config['channels']:
                try:
                    channel = discord.utils.get(guild.channels, id=channel_data['id'])
                    if channel:
                        overwrites = {}
                        for target_id, overwrite_data in channel_data['overwrites'].items():
                            target = guild.get_member(int(target_id)) or guild.get_role(int(target_id))
                            if target:
                                overwrites[target] = discord.PermissionOverwrite.from_pair(
                                    discord.Permissions(overwrite_data['allow']),
                                    discord.Permissions(overwrite_data['deny'])
                                )
                        
                        await channel.edit(
                            name=channel_data['name'],
                            position=channel_data['position'],
                            overwrites=overwrites
                        )
                except Exception as e:
                    logging.error(f"Error restoring channel {channel_data['name']}: {e}")
            
            logging.info(f"Successfully restored configuration for guild {guild.name}")
            return True
        
        except Exception as e:
            logging.error(f"Error restoring guild configuration: {e}")
            return False

# Global config manager instance
server_config_manager = ServerConfigManager()

# --- Otomatik Sunucu Yedekleme Görevi ---
async def auto_backup_server_configs():
    """Düzenli aralıklarla sunucu ayarlarını yedekle"""
    await bot.wait_until_ready()
    
    while not bot.is_closed():
        try:
            # Her sunucu için ayarları yedekle
            for guild in bot.guilds:
                server_config_manager.save_config(guild)
                logging.info(f"Backed up configuration for guild: {guild.name}")
            
            # Belirlenen aralıkta bekle
            await asyncio.sleep(bot_config.ServerBackup.AUTO_BACKUP_INTERVAL)
        
        except Exception as e:
            logging.error(f"Error in auto backup task: {e}")
            # Hata durumunda kısa bir süre bekle ve devam et
            await asyncio.sleep(600)  # 10 dakika bekle

# --- Event Handlers for Security Features ---
@bot.event
async def on_guild_role_delete(role):
    async for entry in role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete):
        await security_monitor.handle_unauthorized_action(role.guild, entry.user, "role_delete")

@bot.event
async def on_guild_channel_delete(channel):
    async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete):
        await security_monitor.handle_unauthorized_action(channel.guild, entry.user, "channel_delete")

@bot.event
async def on_webhook_update(channel):
    async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.webhook_create):
        await security_monitor.handle_unauthorized_action(channel.guild, entry.user, "webhook_create")

@bot.event
async def on_member_ban(guild, user):
    async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
        if not security_monitor.is_trusted(entry.user.id):
            await security_monitor.log_action(guild, "Member Ban", entry.user, f"Banned user: {user}")

# --- Enhanced Message Handler ---
class MessageHandler:
    def __init__(self):
        self.flood_cache = defaultdict(lambda: deque(maxlen=bot_config.Moderation.FLOOD_THRESHOLD))
        self.last_message = defaultdict(str)
        self.message_count = defaultdict(int)
        self.warning_count = defaultdict(int)
        
    async def check_message(self, message):
        """
        Comprehensive message checking with personalized warnings for different rule violations
        """
        # Ignore messages from bots to prevent potential loops
        if message.author.bot:
            logging.debug(f"Ignoring message from bot: {message.author.name}")
            return
        
        # Track user message frequency
        current_time = datetime.datetime.now()
        global user_message_deque
        user_message_deque.append((message, current_time))
        
        # Initialize tracking variables
        violations = []
        warning_reason = None
        
        try:
            # 1. Profanity Check
            if contains_profanity(message.content) or advanced_profanity_check(message.content):
                violations.append("küfür")
                warning_reason = "Küfürlü içerik tespit edildi"
                logging.info(f"Profanity detected in message from {message.author.name}")
                await self.safe_delete_message(message)
            
            # 2. Excessive Capitalization Check
            caps_percentage = sum(1 for c in message.content if c.isupper()) / len(message.content) * 100 if message.content else 0
            if caps_percentage > bot_config.Moderation.MAX_CAPS_PERCENTAGE:
                violations.append("aşırı büyük harf")
                warning_reason = "Aşırı büyük harf kullanımı"
                logging.info(f"Excessive capitalization detected in message from {message.author.name}")
                await self.safe_delete_message(message)
            
            # 3. Flood Protection
            if len(self.flood_cache[message.author.id]) >= bot_config.Moderation.FLOOD_THRESHOLD:
                time_diff = (current_time - self.flood_cache[message.author.id][0]).total_seconds()
                if time_diff < bot_config.Moderation.FLOOD_TIME:
                    violations.append("mesaj seli")
                    warning_reason = "Çok hızlı mesaj gönderimi"
                    logging.info(f"Message flooding detected from {message.author.name}")
                    await self.safe_delete_message(message)
            
            # 4. Duplicate Message Check
            if message.content == self.last_message[message.author.id]:
                self.message_count[message.author.id] += 1
                if self.message_count[message.author.id] >= bot_config.Moderation.DUPLICATE_THRESHOLD:
                    violations.append("tekrarlanan mesaj")
                    warning_reason = "Tekrarlanan mesaj"
                    logging.info(f"Duplicate messages detected from {message.author.name}")
                    await self.safe_delete_message(message)
            else:
                self.last_message[message.author.id] = message.content
                self.message_count[message.author.id] = 1
        
            # 5. Link Safety Check
            if is_link(message.content):
                link_safety = await analyze_link_safety(message.content)
                if not link_safety:
                    violations.append("güvenli olmayan link")
                    warning_reason = "Güvenli olmayan link"
                    logging.info(f"Unsafe link detected in message from {message.author.name}")
                    await self.safe_delete_message(message)
            
            # 6. Mention Spam Check
            mention_count = count_mentions(message)
            if mention_count > bot_config.Moderation.MAX_EMOJI_COUNT:
                violations.append("aşırı kullanıcı etiketi")
                warning_reason = "Çok fazla kullanıcı etiketi"
                logging.info(f"Mention spam detected from {message.author.name}")
                await self.safe_delete_message(message)
            
            # 7. Emoji Spam Check
            if contains_excessive_emojis(message.content):
                violations.append("aşırı emoji")
                warning_reason = "Aşırı emoji kullanımı"
                logging.info(f"Excessive emojis detected in message from {message.author.name}")
                await self.safe_delete_message(message)
        
            # Send personalized warnings for each violation
            if violations:
                logging.warning(f"Violations detected for {message.author.name}: {', '.join(violations)}")
                await self.warn_user(message.author, warning_reason or "Sunucu kurallarını ihlal etme")
    
        except Exception as e:
            logging.error(f"Error in message checking for {message.author.name}: {str(e)}")
            # Optionally, you can add more specific error handling here
    
    async def safe_delete_message(self, message):
        """
        Safely delete a message, handling potential errors
        """
        try:
            # Check if message still exists and bot has permissions
            if message and message.channel and message.author:
                await message.delete()
        except discord.NotFound:
            # Message already deleted
            logging.info(f"Message {message.id} was already deleted.")
        except discord.Forbidden:
            # Bot lacks permissions to delete
            logging.warning(f"Cannot delete message {message.id}. Insufficient permissions.")
        except discord.HTTPException as e:
            # Other HTTP-related errors
            logging.error(f"Error deleting message {message.id}: {e}")
        except Exception as e:
            # Catch any unexpected errors
            logging.error(f"Unexpected error when deleting message: {e}")

    async def warn_user(self, user, reason):
        """
        Send a warning to a user with a detailed message and track warning count
        
        Args:
            user (discord.Member): The user to warn
            reason (str): Reason for the warning
        """
        # Ensure user is a valid Discord member
        if not user:
            logging.error("Attempted to warn a None user")
            return
        
        # Increment warning count
        self.warning_count[user.id] = self.warning_count.get(user.id, 0) + 1
        current_warnings = self.warning_count[user.id]
        max_warnings = bot_config.Moderation.MAX_WARNINGS
        
        # Construct warning message
        warning_message = (
            f"⚠️ **UYARI - {user.name}** ⚠️\n"
            f"Sebep: {reason}\n"
            f"Uyarı Sayısı: {current_warnings}/{max_warnings}\n\n"
            "Sunucu kurallarını ihlal ettiğiniz için bu uyarıyı alıyorsunuz. "
            "Lütfen davranışlarınızı düzeltin, aksi takdirde daha ciddi cezalar alabilirsiniz."
        )
        
        # Attempt to send warning via DM
        try:
            await user.send(warning_message)
            logging.info(f"Warning sent to {user.name} via DM")
        except (discord.Forbidden, discord.HTTPException):
            logging.warning(f"Could not send DM warning to {user.name}")
        
        # Attempt to send warning in the server
        try:
            if hasattr(user, 'guild'):
                # Try to find a general or rules channel
                warning_channels = [
                    channel for channel in user.guild.text_channels 
                    if any(keyword in channel.name.lower() for keyword in ['genel', 'kurallar', 'bilgilendirme', 'sunucu-istekleri', 'general', 'rules'])
                ]
                
                # If no specific channel found, use the first text channel
                if not warning_channels and user.guild.text_channels:
                    warning_channels = [user.guild.text_channels[0]]
                
                # Send warning to the most appropriate channel
                for channel in warning_channels:
                    try:
                        warning_embed = discord.Embed(
                            title="⚠️ Kullanıcı Uyarısı ⚠️",
                            description=f"{user.mention} {warning_message}",
                            color=discord.Color.red()
                        )
                        await channel.send(embed=warning_embed)
                        logging.info(f"Warning sent to channel {channel.name} for {user.name}")
                        break  # Send in only one channel to avoid spam
                    except discord.Forbidden:
                        continue
        except Exception as e:
            logging.error(f"Error sending channel warning for {user.name}: {str(e)}")
        
        # Take action if warning limit exceeded
        if current_warnings >= max_warnings:
            try:
                punishment = 'mute'  
                duration = bot_config.Moderation.MUTE_DURATION_5M  
                
                if punishment == 'mute':
                    await mute_user(user, duration)
                    self.warning_count[user.id] = 0  
                    action_message = f"Kullanıcı {user.name} uyarı limitini aştığı için {duration} saniye susturuldu."
                else:
                    action_message = f"Kullanıcı {user.name} uyarı limitini aştı."
            
                # Log the action
                if hasattr(user, 'guild'):
                    await security_monitor.log_action(
                        user.guild,
                        "Uyarı Limiti Aşıldı",
                        user,
                        f"{action_message}\nToplam Uyarılar: {current_warnings}"
                    )
                    logging.warning(action_message)
                    
                    # Send a final warning about punishment
                    try:
                        punishment_embed = discord.Embed(
                            title="🚫 Ceza Uygulandı 🚫",
                            description=f"{user.mention} {action_message}",
                            color=discord.Color.dark_red()
                        )
                        for channel in user.guild.text_channels:
                            try:
                                await channel.send(embed=punishment_embed)
                                break
                            except discord.Forbidden:
                                continue
                    except Exception as e:
                        logging.error(f"Error sending punishment notification for {user.name}: {str(e)}")
            except Exception as e:
                logging.error(f"Error processing warning limit for {user.name}: {str(e)}")
        else:
            # Log the warning
            try:
                if hasattr(user, 'guild'):
                    await security_monitor.log_action(
                        user.guild,
                        "Uyarı",
                        user,
                        f"{reason}\nUyarı Sayısı: {current_warnings}/{max_warnings}"
                    )
                    logging.info(f"Warning logged for {user.name}: {reason}")
            except Exception as e:
                logging.error(f"Error logging warning for {user.name}: {str(e)}")

handler = MessageHandler()

# --- Event Handlers ---

@bot.event
async def on_member_join(member):
    guild_id = member.guild.id
    member_join_times[guild_id].append(datetime.datetime.now(datetime.timezone.utc))
    await check_for_raid(member.guild)
    account_age = (datetime.datetime.now(datetime.timezone.utc) - member.created_at).total_seconds()
    if account_age < 60 * 60 * 24 * 7:
        logging.warning(f"New member {member.name} has a young account (less than a week old).")
    await collect_user_data(member, member.guild, 'join', None)

@bot.event
async def on_message(message):
    # Ignore bot messages
    if message.author == bot.user:
        return

    await handler.check_message(message)

    # --- Slow Mode Check ---
    user_message_deque = user_messages[message.author.id]
    current_time = datetime.datetime.now(datetime.timezone.utc)

    # Only append if it's a new message, not an edit
    if not message.edited_at:
        user_message_deque.append((message.content, current_time))

    if len(user_message_deque) > 1:
        time_difference = (current_time - user_message_deque[0][1]).total_seconds()
        if time_difference < SLOW_MODE_DELAY:
            warning_message = await message.channel.send(
                f"{message.author.mention}, you are sending messages too quickly. Please wait a moment."
            )
            await handler.safe_delete_message(message)
            logging.warning(f"Deleted message from {message.author.name} due to slow mode.")

            try:
                await asyncio.sleep(10)
                await warning_message.delete()
            except discord.errors.HTTPException:
                logging.error(f"Error deleting warning message for slow mode: {message.author.name}")
            return

    # --- Spam Check ---
    if len(user_message_deque) > SPAM_THRESHOLD and (current_time - user_message_deque[0][1]).total_seconds() <= SPAM_TIME:
        warning_message = await message.channel.send(f"{message.author.mention}, your message was deleted due to spam.")
        await handler.safe_delete_message(message)
        logging.warning(f"Deleted spam message from {message.author.name}.")

        try:
            await asyncio.sleep(10)
            await warning_message.delete()
        except discord.errors.HTTPException:
            logging.error(f"Error deleting warning message for spam: {message.author.name}")
        return

    # --- Duplicate Message Check ---
    message_history[message.author.id].append(message.content)

    if len(message_history[message.author.id]) >= DUPLICATE_MSG_THRESHOLD:
        recent_messages = list(message_history[message.author.id])
        if all(is_similar(recent_messages[-1], msg) for msg in recent_messages[:-1]):
            warning_message = await message.channel.send(
                f"{message.author.mention}, your message was deleted because it was a duplicate."
            )
            await handler.safe_delete_message(message)
            logging.warning(f"Deleted duplicate message from {message.author.name}.")
            try:
                await asyncio.sleep(10)
                await warning_message.delete()
            except discord.errors.HTTPException:
                logging.error(f"Error deleting warning message for duplicate: {message.author.name}")
            return

    # --- Capitalization Check ---
    if len(message.content) > 0:
        capitalization_ratio = sum(char.isupper() for char in message.content) / len(message.content) * 100 if message.content else 0
        if capitalization_ratio > CAPITALIZATION_THRESHOLD:
            warning_message = await message.channel.send(
                f"{message.author.mention}, your message was deleted due to excessive capitalization."
            )
            await handler.safe_delete_message(message)
            logging.warning(f"Deleted message with excessive capitalization from {message.author.name}.")
            try:
                await asyncio.sleep(10)
                await warning_message.delete()
            except discord.errors.HTTPException:
                logging.error(f"Error deleting warning message for capitalization: {message.author.name}")
            return

    # ---  Emoji Check ---
    if contains_excessive_emojis(message.content):
        warning_message = await message.channel.send(
            f"{message.author.mention}, your message was deleted due to excessive emojis."
        )
        await handler.safe_delete_message(message)
        logging.warning(f"Deleted message with excessive emojis from {message.author.name}.")
        try:
            await asyncio.sleep(10)
            await warning_message.delete()
        except discord.errors.HTTPException:
            logging.error(f"Error deleting warning message for emojis: {message.author.name}")
        return

    # --- Link Check ---
    if is_link(message.content):
        link = re.search(r'(https?://\S+)', message.content).group(0)
        if not await analyze_link_safety(link):
            warning_message = await message.channel.send(
                f"{message.author.mention}, your message contained an unsafe link and has been deleted."
            )
            await handler.safe_delete_message(message)
            logging.warning(f"Deleted message with unsafe link from {message.author.name}.")
            try:
                await asyncio.sleep(10)
                await warning_message.delete()
            except discord.errors.HTTPException:
                logging.error(f"Error deleting warning message for unsafe link: {message.author.name}")
        else:
            warning_message = await message.channel.send(f"{message.author.mention}, your message contained a safe link.")
            try:
                await asyncio.sleep(10)
                await warning_message.delete()
            except discord.errors.HTTPException:
                logging.error(f"Error deleting warning message for safe link: {message.author.name}")
        return

    # --- File/Image Check ---
    if message.attachments:
        for attachment in message.attachments:
            try:
                file_url = attachment.url
                if not await analyze_file_safety(file_url):
                    warning_message = await message.channel.send(
                        f"{message.author.mention}, your message contained an unsafe file and has been deleted."
                    )
                    await handler.safe_delete_message(message)
                    logging.warning(f"Deleted message with unsafe file from {message.author.name}.")
                    try:
                        await asyncio.sleep(10)
                        await warning_message.delete()
                    except discord.errors.HTTPException:
                        logging.error(f"Error deleting warning message for unsafe file: {message.author.name}")
                else:
                    warning_message = await message.channel.send(
                        f"{message.author.mention}, your message contained a safe file."
                    )
                    try:
                        await asyncio.sleep(10)
                        await warning_message.delete()
                    except discord.errors.HTTPException:
                        logging.error(f"Error deleting warning message for safe file: {message.author.name}")

                # Image Duplication Check (If applicable)
                if attachment.url.lower().endswith(('png', 'jpg', 'jpeg', 'gif')):
                    image_hash = await hash_image(attachment.url)
                    if image_hash and is_duplicate_image(message.author.id, image_hash, current_time):
                        warning_message = await message.channel.send(
                            f"{message.author.mention}, you already posted this image!"
                        )
                        await handler.safe_delete_message(message)
                        logging.warning(f"Deleted duplicate image from {message.author.name}.")
                        try:
                            await asyncio.sleep(10)
                            await warning_message.delete()
                        except discord.errors.HTTPException:
                            logging.error(
                                f"Error deleting warning message for duplicate image: {message.author.name}"
                            )
                        return
                    if image_hash:
                        user_image_hashes[message.author.id].append((image_hash, current_time))
            except Exception as e:
                logging.error(f"Error analyzing file attachment: {e}")
            return

    await collect_user_data(message.author, message.guild, 'message', message.content)

@bot.event
async def on_member_update(before, after):
    if before.roles != after.roles:
        await collect_user_data(after, after.guild, 'role_update', after.roles)

@bot.event
async def on_raw_reaction_add(payload):
    await collect_user_data(await bot.fetch_user(payload.user_id), await bot.fetch_guild(payload.guild_id), 'interaction', payload.emoji.name)

@bot.event
async def on_raw_reaction_remove(payload):
    await collect_user_data(await bot.fetch_user(payload.user_id), await bot.fetch_guild(payload.guild_id), 'interaction', payload.emoji.name)

@bot.event
async def on_ready():
    logging.info(f'Logged in as {bot.user.name}')
    bot.loop.create_task(update_status())
    bot.loop.create_task(auto_backup_server_configs())
    
    # Mevcut sunucuların ilk yedeklemesini yap
    for guild in bot.guilds:
        server_config_manager.save_config(guild)
        logging.info(f"Initial backup for guild: {guild.name}")

# --- Security Event Handlers ---
@bot.event
async def on_guild_update(before, after):
    """Sunucu ayarları değişikliklerini izle"""
    # Yetkisiz kullanıcılar tarafından yapılan değişiklikleri tespit et
    async for entry in after.audit_logs(limit=1, action=discord.AuditLogAction.guild_update):
        if not security_monitor.is_trusted(entry.user.id):
            # Değişiklikleri geri al
            await server_config_manager.restore_config(after)
            await security_monitor.log_action(
                after, 
                "Unauthorized Guild Update", 
                entry.user, 
                "Unauthorized server settings modification detected and reverted"
            )

# --- Performans Optimizasyonu ---
class PerformanceOptimizer:
    def __init__(self, bot):
        self.bot = bot
        self.cache = {
            'user_actions': LRUCache(maxsize=10000),  # En son kullanılan 10000 kullanıcı eylemini önbellekle
            'guild_configs': LRUCache(maxsize=100),   # En son kullanılan 100 sunucu yapılandırmasını önbellekle
            'rate_limits': defaultdict(lambda: defaultdict(int))  # Hız sınırlaması için önbellek
        }
        self.task_queue = asyncio.Queue()
        self.processing_tasks = set()
    
    async def process_high_priority_tasks(self):
        """Yüksek öncelikli görevleri işle"""
        while True:
            try:
                priority, task = await self.task_queue.get()
                
                # Eş zamanlı işlem sayısını sınırla
                if len(self.processing_tasks) < bot_config.Performance.MAX_CONCURRENT_TASKS:
                    task_coro = asyncio.create_task(task)
                    self.processing_tasks.add(task_coro)
                    task_coro.add_done_callback(self.processing_tasks.discard)
                
                self.task_queue.task_done()
            except Exception as e:
                logging.error(f"High priority task processing error: {e}")
                await asyncio.sleep(1)
    
    def is_rate_limited(self, user_id, action_type, limit=5, window=10):
        """Kullanıcı için hız sınırlaması kontrolü"""
        current_time = time.time()
        user_actions = self.cache['rate_limits'][user_id][action_type]
        
        # Zaman penceresinin dışındaki eylemleri temizle
        user_actions[:] = [t for t in user_actions if current_time - t < window]
        
        if len(user_actions) >= limit:
            return True
        
        user_actions.append(current_time)
        return False
    
    async def cache_guild_config(self, guild):
        """Sunucu yapılandırmasını önbellekle"""
        if guild.id not in self.cache['guild_configs']:
            config = await server_config_manager.get_cached_config(guild)
            self.cache['guild_configs'][guild.id] = config
    
    async def log_action_with_priority(self, guild, action_type, user, details, priority=1):
        """Yüksek performanslı eylem günlüğü"""
        task = security_monitor.log_action(guild, action_type, user, details)
        await self.task_queue.put((priority, task))

# Performans optimizasyonu için gerekli ek kütüphaneler
from functools import lru_cache
from cachetools import LRUCache
import time

# Global performans optimize edici
performance_optimizer = PerformanceOptimizer(bot)

# Sunucu Yapılandırma Yöneticisini Optimize Et
class ServerConfigManager:
    def __init__(self, config_file='server_config_backup.json'):
        self.config_file = config_file
        self.current_config = {}
        self.config_lock = asyncio.Lock()  # Eş zamanlı erişimi kontrol etmek için kilit
        self.load_config()
    
    @lru_cache(maxsize=100)  # Önbelleğe alınmış yapılandırma getirme
    async def get_cached_config(self, guild):
        """Sunucu yapılandırmasını hızlı bir şekilde getir"""
        async with self.config_lock:
            return self.current_config.get(str(guild.id), {})
    
    def save_config(self, guild):
        """Optimize edilmiş sunucu ayarları kaydetme"""
        try:
            # Performans için sadece kritik ayarları kaydet
            guild_config = {
                'critical_settings': {
                    'name': guild.name,
                    'verification_level': guild.verification_level.value,
                    'roles_count': len(guild.roles),
                    'channels_count': len(guild.channels)
                },
                'detailed_backup_time': datetime.datetime.now().isoformat()
            }
            
            # Kritik roller ve kanalların özet bilgileri
            guild_config['roles'] = [
                {
                    'id': role.id,
                    'name': role.name,
                    'permissions_hash': hash(role.permissions.value)
                } for role in guild.roles[:bot_config.ServerBackup.MAX_ROLES_IN_SUMMARY]
            ]
            
            guild_config['channels'] = [
                {
                    'id': channel.id,
                    'name': channel.name,
                    'type': str(channel.type),
                    'overwrites_hash': hash(tuple(channel.overwrites.items()))
                } for channel in guild.channels[:bot_config.ServerBackup.MAX_CHANNELS_IN_SUMMARY]
            ]
            
            # Dosyaya kaydetme
            with open(self.config_file, 'w') as f:
                json.dump(self.current_config, f, indent=4)
            
            # Performans optimizasyonu için önbelleğe al
            performance_optimizer.cache['guild_configs'][guild.id] = guild_config
            
        except Exception as e:
            logging.error(f"Sunucu ayarları kaydedilirken hata: {e}")

# Performans için olay işleyicilerini optimize et
@bot.event
async def on_guild_update(before, after):
    """Sunucu güncellemelerini optimize edilmiş şekilde işle"""
    # Önbellekten hızlı yapılandırma kontrolü
    await performance_optimizer.cache_guild_config(after)
    
    async for entry in after.audit_logs(limit=1, action=discord.AuditLogAction.guild_update):
        if not security_monitor.is_trusted(entry.user.id):
            # Yüksek öncelikli görev olarak işle
            await performance_optimizer.log_action_with_priority(
                after, 
                "Unauthorized Guild Update", 
                entry.user, 
                "Unauthorized server settings modification detected",
                priority=2
            )
            
            # Hız sınırlaması kontrolü
            if not performance_optimizer.is_rate_limited(entry.user.id, 'guild_update'):
                await server_config_manager.restore_config(after)

# Performans için arka plan görevi
async def performance_monitoring_task():
    """Performans ve kaynak kullanımını izleme"""
    while True:
        try:
            # Önbellek boyutunu ve performans istatistiklerini logla
            logging.info(f"User Action Cache Size: {len(performance_optimizer.cache['user_actions'])}")
            logging.info(f"Guild Config Cache Size: {len(performance_optimizer.cache['guild_configs'])}")
            logging.info(f"Active Processing Tasks: {len(performance_optimizer.processing_tasks)}")
            
            await asyncio.sleep(bot_config.Performance.MONITORING_INTERVAL)
        except Exception as e:
            logging.error(f"Performance monitoring error: {e}")
            await asyncio.sleep(60)

# Performans izleme görevini başlat
@bot.event
async def on_ready():
    bot.loop.create_task(performance_monitoring_task())
    bot.loop.create_task(performance_optimizer.process_high_priority_tasks())
    logging.info(f'Logged in as {bot.user.name}')
    bot.loop.create_task(update_status())
    bot.loop.create_task(auto_backup_server_configs())
    
    # Mevcut sunucuların ilk yedeklemesini yap
    for guild in bot.guilds:
        server_config_manager.save_config(guild)
        logging.info(f"Initial backup for guild: {guild.name}")

# --- Run Bot ---

async def mute_user(user, duration=30):
    """
    Mute a user for a specified duration.
    
    Args:
        user (discord.Member): The user to mute
        duration (int, optional): Mute duration in seconds. Defaults to 30.
    """
    try:
        # Find the muted role or create it if it doesn't exist
        muted_role = discord.utils.get(user.guild.roles, name="Muted")
        if not muted_role:
            muted_role = await user.guild.create_role(name="Muted", reason="Auto-created for user muting")
            
            # Modify channel permissions to prevent the muted role from sending messages
            for channel in user.guild.channels:
                await channel.set_permissions(muted_role, send_messages=False)
        
        # Add the muted role to the user
        await user.add_roles(muted_role, reason="Violated server rules")
        
        # Log the mute action
        logging.warning(f"Muted {user.name} for {duration} seconds")
        
        # Schedule role removal after duration
        await asyncio.sleep(duration)
        await user.remove_roles(muted_role, reason="Mute duration expired")
        
    except discord.Forbidden:
        logging.error(f"Failed to mute {user.name}: Insufficient permissions")
    except discord.HTTPException as e:
        logging.error(f"Failed to mute {user.name}: {str(e)}")

bot.run(bot_config.TOKEN)

# --- Advanced Security Event Handlers ---
@bot.event
async def on_bot_add(guild):
    """Handle bot additions to the server"""
    async with guild.audit_logs(limit=1, action=discord.AuditLogAction.bot_add).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Remove the added bot
                    added_bot = log.target
                    await guild.kick(added_bot)
                    
                    # Log the action
                    security_monitor.log_unauthorized_action(
                        guild.id,
                        "BOT_ADD_ATTEMPT",
                        f"Unauthorized bot addition by {log.user.name} (ID: {log.user.id})"
                    )
                    
                    # Punish the user who added the bot
                    await mute_user(log.user, MUTE_DURATION_5M)
                except Exception as e:
                    logging.error(f"Error handling unauthorized bot addition: {e}")

@bot.event
async def on_member_ban(guild, user):
    """Enhanced ban protection"""
    async with guild.audit_logs(limit=1, action=discord.AuditLogAction.ban).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Unban the member if the banner doesn't have permission
                    await guild.unban(user)
                    await mute_user(log.user, MUTE_DURATION_5M)
                    security_monitor.log_unauthorized_action(
                        guild.id,
                        "UNAUTHORIZED_BAN",
                        f"Unauthorized ban attempt by {log.user.name} (ID: {log.user.id})"
                    )
                except Exception as e:
                    logging.error(f"Error handling unauthorized ban: {e}")

@bot.event
async def on_member_remove(member):
    """Enhanced kick protection"""
    async with member.guild.audit_logs(limit=1, action=discord.AuditLogAction.kick).flatten() as logs:
        if logs and logs[0].target.id == member.id:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Log the unauthorized kick
                    security_monitor.log_unauthorized_action(
                        member.guild.id,
                        "UNAUTHORIZED_KICK",
                        f"Unauthorized kick by {log.user.name} (ID: {log.user.id})"
                    )
                    
                    # Punish the kicker
                    await mute_user(log.user, MUTE_DURATION_5M)
                    
                    # Try to reinvite the kicked member if possible
                    try:
                        invite = await member.guild.text_channels[0].create_invite(max_uses=1, max_age=300)
                        await member.send(f"You were kicked by an unauthorized user. Here's an invite back: {invite}")
                    except:
                        pass
                except Exception as e:
                    logging.error(f"Error handling unauthorized kick: {e}")

@bot.event
async def on_guild_channel_create(channel):
    """Enhanced channel creation protection"""
    async with channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_create).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Delete the unauthorized channel
                    await channel.delete()
                    await mute_user(log.user, MUTE_DURATION_5M)
                    security_monitor.log_unauthorized_action(
                        channel.guild.id,
                        "UNAUTHORIZED_CHANNEL_CREATE",
                        f"Unauthorized channel creation by {log.user.name} (ID: {log.user.id})"
                    )
                except Exception as e:
                    logging.error(f"Error handling unauthorized channel creation: {e}")

@bot.event
async def on_guild_channel_delete(channel):
    """Enhanced channel deletion protection"""
    async with channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Log the unauthorized deletion
                    security_monitor.log_unauthorized_action(
                        channel.guild.id,
                        "UNAUTHORIZED_CHANNEL_DELETE",
                        f"Unauthorized channel deletion by {log.user.name} (ID: {log.user.id})"
                    )
                    
                    # Recreate the channel with same settings
                    new_channel = await channel.clone()
                    await new_channel.edit(position=channel.position)
                    
                    # Punish the user
                    await mute_user(log.user, MUTE_DURATION_5M)
                except Exception as e:
                    logging.error(f"Error handling unauthorized channel deletion: {e}")

@bot.event
async def on_guild_role_create(role):
    """Enhanced role creation protection"""
    async with role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_create).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Delete the unauthorized role
                    await role.delete()
                    await mute_user(log.user, MUTE_DURATION_5M)
                    security_monitor.log_unauthorized_action(
                        role.guild.id,
                        "UNAUTHORIZED_ROLE_CREATE",
                        f"Unauthorized role creation by {log.user.name} (ID: {log.user.id})"
                    )
                except Exception as e:
                    logging.error(f"Error handling unauthorized role creation: {e}")

@bot.event
async def on_guild_role_delete(role):
    """Enhanced role deletion protection"""
    async with role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Log the unauthorized deletion
                    security_monitor.log_unauthorized_action(
                        role.guild.id,
                        "UNAUTHORIZED_ROLE_DELETE",
                        f"Unauthorized role deletion by {log.user.name} (ID: {log.user.id})"
                    )
                    
                    # Recreate the role with same settings
                    new_role = await role.guild.create_role(
                        name=role.name,
                        permissions=role.permissions,
                        colour=role.colour,
                        hoist=role.hoist,
                        mentionable=role.mentionable
                    )
                    
                    # Punish the user
                    await mute_user(log.user, MUTE_DURATION_5M)
                except Exception as e:
                    logging.error(f"Error handling unauthorized role deletion: {e}")

@bot.event
async def on_guild_role_update(before, after):
    """Enhanced role update protection"""
    async with after.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_update).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Revert dangerous permission changes
                    dangerous_permissions = [
                        "administrator",
                        "ban_members",
                        "kick_members",
                        "manage_channels",
                        "manage_guild",
                        "manage_roles",
                        "manage_webhooks"
                    ]
                    
                    permissions_changed = False
                    for perm in dangerous_permissions:
                        if getattr(after.permissions, perm) and not getattr(before.permissions, perm):
                            permissions_changed = True
                            break
                    
                    if permissions_changed:
                        await after.edit(permissions=before.permissions)
                        await mute_user(log.user, MUTE_DURATION_5M)
                        security_monitor.log_unauthorized_action(
                            after.guild.id,
                            "UNAUTHORIZED_ROLE_UPDATE",
                            f"Unauthorized role permission update by {log.user.name} (ID: {log.user.id})"
                        )
                except Exception as e:
                    logging.error(f"Error handling unauthorized role update: {e}")

@bot.event
async def on_webhooks_update(channel):
    """Enhanced webhook protection"""
    async with channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.webhook_create).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Delete unauthorized webhooks
                    webhooks = await channel.webhooks()
                    for webhook in webhooks:
                        if webhook.user.id == log.user.id:
                            await webhook.delete()
                    
                    await mute_user(log.user, MUTE_DURATION_5M)
                    security_monitor.log_unauthorized_action(
                        channel.guild.id,
                        "UNAUTHORIZED_WEBHOOK_CREATE",
                        f"Unauthorized webhook creation by {log.user.name} (ID: {log.user.id})"
                    )
                except Exception as e:
                    logging.error(f"Error handling unauthorized webhook creation: {e}")

@bot.event
async def on_guild_update(before, after):
    """Enhanced server settings protection"""
    async with after.audit_logs(limit=1, action=discord.AuditLogAction.guild_update).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    changes_made = False
                    
                    # Check for vanity URL changes
                    if hasattr(before, 'vanity_url_code') and before.vanity_url_code != after.vanity_url_code:
                        await after.edit(vanity_url_code=before.vanity_url_code)
                        changes_made = True
                    
                    # Check for icon changes
                    if before.icon != after.icon:
                        await after.edit(icon=before.icon.url if before.icon else None)
                        changes_made = True
                    
                    if changes_made:
                        await mute_user(log.user, MUTE_DURATION_5M)
                        security_monitor.log_unauthorized_action(
                            after.id,
                            "UNAUTHORIZED_SERVER_UPDATE",
                            f"Unauthorized server settings update by {log.user.name} (ID: {log.user.id})"
                        )
                except Exception as e:
                    logging.error(f"Error handling unauthorized server update: {e}")

@bot.event
async def on_member_ban(guild, user):
    """Enhanced @everyone/@here protection"""
    async with guild.audit_logs(limit=1, action=discord.AuditLogAction.ban).flatten() as logs:
        if logs:
            log = logs[0]
            if not log.user.guild_permissions.administrator:
                try:
                    # Unban the member if the banner doesn't have permission
                    await guild.unban(user)
                    await mute_user(log.user, MUTE_DURATION_5M)
                    security_monitor.log_unauthorized_action(
                        guild.id,
                        "UNAUTHORIZED_BAN",
                        f"Unauthorized ban attempt by {log.user.name} (ID: {log.user.id})"
                    )
                except Exception as e:
                    logging.error(f"Error handling unauthorized ban: {e}")

@bot.event
async def on_message(message):
    """Enhanced @everyone/@here protection"""
    if message.mention_everyone and not message.author.guild_permissions.administrator:
        try:
            # Delete the message
            await handler.safe_delete_message(message)
            
            # Punish the user
            await mute_user(message.author, MUTE_DURATION_30S)
            
            security_monitor.log_unauthorized_action(
                message.guild.id,
                "UNAUTHORIZED_EVERYONE_MENTION",
                f"Unauthorized @everyone/@here mention by {message.author.name} (ID: {message.author.id})"
            )
        except Exception as e:
            logging.error(f"Error handling unauthorized everyone/here mention: {e}")
    
    await bot.process_commands(message)
