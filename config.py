import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Bot Configuration
class BotConfig:
    # Discord Bot Settings
    TOKEN = os.getenv('DISCORD_TOKEN')
    COMMAND_PREFIX = '/'
    
    # API Keys
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    
    # Logging Configuration
    LOGGING_LEVEL = 'DEBUG'
    LOGGING_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    
    # Moderation Thresholds
    class Moderation:
        # Spam Protection
        SPAM_TIME = 1
        SPAM_THRESHOLD = 4
        DUPLICATE_RESET_TIME = 60
        DUPLICATE_MSG_THRESHOLD = 3
        
        # Flood Protection
        FLOOD_THRESHOLD = 5
        FLOOD_TIME = 10
        DUPLICATE_THRESHOLD = 3
        
        # Content Filtering
        MAX_CAPS_PERCENTAGE = 70
        MAX_EMOJI_COUNT = 10
        PROFANITY_WARN_THRESHOLD = 2
        LINK_WHITELIST = ['discord.com', 'discordapp.com']
        
        # Auto-Moderation Actions
        MUTE_DURATION_1H = 3600
        MUTE_DURATION_24H = 86400
        BAN_DURATION_TEMP = 604800  # 7 days
        MAX_WARNINGS = 5
        WARNING_EXPIRE_DAYS = 30
        
        # Raid Protection
        RAID_THRESHOLD = 10
        RAID_TIME = 300
        JOIN_RATE_THRESHOLD = 5
        RAID_JOIN_THRESHOLD = 10
        RAID_JOIN_TIME = 60
        RAID_NEW_ACCOUNT_DAYS = 7
        
        # Message Filtering
        CAPITALIZATION_THRESHOLD = 0.7
        EMOJI_THRESHOLD = 5
        MESSAGE_VOLUME_THRESHOLD = 10
        
        # Warnings and Mutes
        WARNING_LIMIT = 5
        MUTE_DURATION_30S = 30
        MUTE_DURATION_5M = 300
    
    # Security Settings
    class Security:
        LOG_CHANNEL = 'security-logs'
        TRUSTED_ROLES = ['Admin', 'Moderator']
        AUDIT_LOG_LIMIT = 100
        RECOVERY_BACKUP_INTERVAL = 3600  # 1 hour
        MAX_MENTIONS_PER_MESSAGE = 5
        MAX_ROLE_CREATIONS_PER_HOUR = 5
        MAX_CHANNEL_CREATIONS_PER_HOUR = 5
        MAX_WEBHOOK_CREATIONS_PER_HOUR = 3
        ANTI_RAID_ENABLED = True
        AUTO_BACKUP_ENABLED = True
        
    # Image and Link Safety
    class Safety:
        IMAGE_DUPLICATE_TIME_WINDOW = 60
        SLOW_MODE_DELAY = 5
    
    # File Paths
    class FilePaths:
        # Mevcut dosya yolları
        USER_DATA_FILE = 'user_data.json'
        
        # Yeni sunucu yedekleme dosyası
        SERVER_CONFIG_BACKUP = 'server_config_backup.json'
    
    # Küfür ve içerik filtreleme ayarları
    class ContentFilter:
        # Küfür tespiti için benzerlik eşiği
        PROFANITY_SIMILARITY_THRESHOLD = 80
        
        # Küfür listesi yolu
        PROFANITY_LIST_PATH = 'profanity_list.txt'
        
        # Küfür için otomatik eylemler
        AUTO_DELETE_PROFANITY = True
        MAX_PROFANITY_WARNINGS = 3
        
        # Küfür için ceza seviyeleri
        PENALTIES = {
            1: 'warning',     # İlk ihlalde uyarı
            2: 'mute_5m',     # İkinci ihlalde 5 dakika susturma
            3: 'mute_1h',     # Üçüncü ihlalde 1 saat susturma
            4: 'temp_ban'     # Dördüncü ihlalde geçici ban
        }
    
    # Enhanced Security Protection Settings
    class SecurityProtection:
        # Role Protection Levels
        ROLE_PROTECTION_LEVELS = {
            'none': 0,     # No protection
            'basic': 1,    # Prevent critical role deletions/updates
            'strict': 2    # Complete role modification prevention
        }
        
        # Channel Protection Levels
        CHANNEL_PROTECTION_LEVELS = {
            'none': 0,     # No protection
            'basic': 1,    # Prevent critical channel deletions/updates
            'strict': 2    # Complete channel modification prevention
        }
        
        # Server Update Protection Levels
        SERVER_UPDATE_PROTECTION_LEVELS = {
            'none': 0,     # No protection
            'basic': 1,    # Prevent critical server changes
            'strict': 2    # Complete server update prevention
        }
        
        # Member Update Protection Levels
        MEMBER_UPDATE_PROTECTION_LEVELS = {
            'none': 0,     # No protection
            'basic': 1,    # Prevent critical member changes
            'strict': 2    # Complete member update prevention
        }
        
        # Protection Settings
        MAX_PROTECTED_ROLES_PER_GUILD = 10
        MAX_PROTECTED_CHANNELS_PER_GUILD = 10
        MAX_PROTECTED_MEMBERS_PER_GUILD = 20
        MAX_PROTECTED_BOTS_PER_GUILD = 5
        
        # Unauthorized Action Logging
        LOG_UNAUTHORIZED_ACTIONS = True
        MAX_UNAUTHORIZED_ACTION_LOGS = 100
        
        # Protection Bypass Roles
        BYPASS_PROTECTION_ROLES = ['Admin', 'Owner']
        
        # Default Protection Configurations
        DEFAULT_ROLE_PROTECTION = 'basic'
        DEFAULT_CHANNEL_PROTECTION = 'basic'
        DEFAULT_SERVER_UPDATE_PROTECTION = 'basic'
        DEFAULT_MEMBER_UPDATE_PROTECTION = 'basic'
        
        # Protection Violation Penalties
        VIOLATION_COOLDOWN_DURATION = 3600  # 1 hour
        MAX_PROTECTION_VIOLATIONS = 3
        
        # Specific Protection Features
        PROTECT_ADMIN_ROLES = True
        PROTECT_SYSTEM_CHANNELS = True
        PROTECT_AUDIT_LOG_CHANNELS = True
        
        # Bot Protection
        PROTECT_CRITICAL_BOTS = True
        BOT_PROTECTION_WHITELIST = []  # List of bot IDs to always protect
        
        # Kick and Ban Protection
        MAX_PROTECTED_USERS_FROM_KICK = 10
        MAX_PROTECTED_USERS_FROM_BAN = 10
        
        # Logging and Notification
        NOTIFY_ON_PROTECTION_VIOLATION = True
        PROTECTION_VIOLATION_NOTIFICATION_CHANNEL = 'security-alerts'
    
    # Performans Optimizasyon Ayarları
    class Performance:
        # Eş zamanlı işlem sınırları
        MAX_CONCURRENT_TASKS = 50
        MAX_QUEUE_SIZE = 1000
        
        # Önbellek ayarları
        USER_ACTION_CACHE_SIZE = 10000
        GUILD_CONFIG_CACHE_SIZE = 100
        
        # İzleme aralıkları
        MONITORING_INTERVAL = 300  # 5 dakikada bir performans izleme
        CACHE_CLEANUP_INTERVAL = 3600  # 1 saatte bir önbellek temizliği
        
        # Hız sınırlama ayarları
        RATE_LIMIT_WINDOW = 10  # Saniye
        RATE_LIMIT_MAX_ACTIONS = 5
    
    # Sunucu yedekleme ayarları
    class ServerBackup:
        # Otomatik yedekleme aralığı (saniye)
        AUTO_BACKUP_INTERVAL = 3600  # 1 saat
        
        # Maksimum yedek sayısı
        MAX_BACKUP_COUNT = 5
        
        # Yedekleme detay seviyesi
        BACKUP_DETAIL_LEVEL = 'high'  # 'low', 'medium', 'high'
        
        # Kritik ayarları yedekle
        CRITICAL_SETTINGS = [
            'name', 
            'verification_level', 
            'roles', 
            'channels', 
            'permissions'
        ]
        
        # Yedeklemede özet için maks eleman sayısı
        MAX_ROLES_IN_SUMMARY = 20
        MAX_CHANNELS_IN_SUMMARY = 50
        
        # Kritik ayarların hash'lenmesi için önbellek
        USE_CONFIG_HASH_CACHE = True
        CONFIG_HASH_CACHE_SIZE = 500
    
# Export configuration
bot_config = BotConfig()
