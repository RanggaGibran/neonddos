package id.neonddos;

import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.List;
import java.util.UUID;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;

/**
 * Plugin NeonDDoS untuk perlindungan server Minecraft dari serangan DDoS
 */
public class neonddos extends JavaPlugin implements Listener {
    private static final Logger LOGGER = Logger.getLogger("neonddos");
    private ConnectionMonitor connectionMonitor;
    private DdosDetector ddosDetector;
    private FirewallManager firewallManager;
    private NotificationSystem notificationSystem;
    private AnalyticsSystem analyticsSystem;
    private TrafficPrioritizer trafficPrioritizer;
    private TCPConnectionFilter tcpConnectionFilter;
    private GeoIPFilter geoIPFilter;
    private MLEngine mlEngine;

    @Override
    public void onEnable() {
        // Simpan konfigurasi default jika belum ada
        saveDefaultConfig();
        
        // Inisialisasi Connection Monitor
        connectionMonitor = new ConnectionMonitor(this);
        
        // Daftarkan event listener
        getServer().getPluginManager().registerEvents(connectionMonitor, this);
        getServer().getPluginManager().registerEvents(this, this);
        
        // Konfigurasi dari config.yml
        loadConfiguration();
        
        // Inisialisasi NotificationSystem
        notificationSystem = new NotificationSystem(this);
        
        // Inisialisasi DDoS Detector yang lebih canggih
        ddosDetector = new DdosDetector(this, connectionMonitor);
        
        // Inisialisasi Firewall Manager
        firewallManager = new FirewallManager(this);
        
        // Inisialisasi Analytics System
        analyticsSystem = new AnalyticsSystem(this);
        
        // Inisialisasi Traffic Prioritizer
        trafficPrioritizer = new TrafficPrioritizer(this);
        
        // Inisialisasi TCP Connection Filter (jika belum ada)
        tcpConnectionFilter = new TCPConnectionFilter(this);
        
        // Inisialisasi GeoIP Filter (jika belum ada)
        geoIPFilter = new GeoIPFilter(this);
        
        // Inisialisasi Machine Learning Engine
        mlEngine = new MLEngine(this);
        
        // Notifikasi sistem aktif
        notificationSystem.sendInfoNotification("Sistem perlindungan aktif dan memantau koneksi");
        
        LOGGER.info("NeonDDoS telah diaktifkan - Melindungi server dari serangan DDoS");
    }

    @Override
    public void onDisable() {
        // Bersihkan aturan firewall jika diperlukan
        if (firewallManager != null) {
            firewallManager.cleanup();
        }
        
        LOGGER.info("NeonDDoS telah dinonaktifkan");
    }
    
    /**
     * Muat konfigurasi dari file config.yml
     */
    private void loadConfiguration() {
        // Coba ambil dari config, atau gunakan default
        int connectionThreshold = getConfig().getInt("connection.threshold", 10);
        long timeWindow = getConfig().getLong("connection.timeWindow", 10000);
        long blockDuration = getConfig().getLong("connection.blockDuration", 60000);
        
        // Terapkan konfigurasi ke Connection Monitor
        connectionMonitor.setConnectionThreshold(connectionThreshold);
        connectionMonitor.setTimeWindow(timeWindow);
        connectionMonitor.setBlockDuration(blockDuration);
        
        LOGGER.info("Konfigurasi NeonDDoS dimuat: " +
                    "threshold=" + connectionThreshold + ", " +
                    "timeWindow=" + (timeWindow/1000) + "s, " +
                    "blockDuration=" + (blockDuration/1000) + "s");
        
        // Tambahkan konfigurasi untuk Traffic Prioritizer jika perlu
    }
    
    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (player.getAddress() != null) {
            String ip = player.getAddress().getAddress().getHostAddress();
            
            // Update Traffic Prioritizer untuk melacak player
            if (trafficPrioritizer != null) {
                trafficPrioritizer.handlePlayerJoin(ip, player.getUniqueId());
            }
        }
    }
    
    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        if (player.getAddress() != null) {
            String ip = player.getAddress().getAddress().getHostAddress();
            
            // Update Traffic Prioritizer saat player disconnect
            if (trafficPrioritizer != null) {
                trafficPrioritizer.handlePlayerQuit(ip);
            }
        }
    }
    
    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (command.getName().equalsIgnoreCase("neonddos")) {
            if (args.length == 0) {
                sender.sendMessage("§a=== §eNeonDDoS Protection §a===");
                sender.sendMessage("§7/neonddos status - Menampilkan status proteksi");
                sender.sendMessage("§7/neonddos stats - Menampilkan statistik serangan");
                sender.sendMessage("§7/neonddos firewall - Menampilkan status firewall");
                sender.sendMessage("§7/neonddos whitelist <add|remove|list> <ip> - Kelola whitelist firewall");
                sender.sendMessage("§7/neonddos notify <enable|disable> <ingame|discord|email> - Kelola notifikasi");
                sender.sendMessage("§7/neonddos analytics - Menampilkan analisis lanjutan serangan");
                sender.sendMessage("§7/neonddos falsepositive <ip> - Tandai IP sebagai false positive");
                sender.sendMessage("§7/neonddos traffic - Statistik prioritas traffic");
                sender.sendMessage("§7/neonddos settraffic <param> <nilai> - Atur prioritas traffic");
                sender.sendMessage("§7/neonddos ml - Statistik Machine Learning");
                sender.sendMessage("§7/neonddos mltrain - Training manual model ML");
                sender.sendMessage("§7/neonddos toggleml - Aktifkan/nonaktifkan ML");
                sender.sendMessage("§7/neonddos testdiscord - Test pengiriman notifikasi Discord");
                return true;
            }
            
            if (args[0].equalsIgnoreCase("status")) {
                sender.sendMessage("§a=== §eStatus NeonDDoS §a===");
                sender.sendMessage("§7Koneksi aktif: §f" + connectionMonitor.getCurrentConnections().size());
                return true;
            }
            
            if (args[0].equalsIgnoreCase("stats")) {
                Map<String, Object> stats = ddosDetector.getStatistics();
                
                sender.sendMessage("§a=== §eStatistik Serangan NeonDDoS §a===");
                sender.sendMessage("§7Serangan terdeteksi: §f" + stats.get("detectedAttacks"));
                sender.sendMessage("§7IP diblokir: §f" + stats.get("blockedIps"));
                sender.sendMessage("§7Monitoring aktif: §f" + stats.get("activeMonitoring"));
                
                @SuppressWarnings("unchecked")
                java.util.List<String> blockedIps = (java.util.List<String>) stats.get("blockedIpList");
                if (!blockedIps.isEmpty()) {
                    sender.sendMessage("§7IP yang diblokir:");
                    for (String ip : blockedIps) {
                        sender.sendMessage("§c - " + ip);
                    }
                }
                return true;
            }
            
            if (args[0].equalsIgnoreCase("analytics")) {
                Map<String, Object> analytics = analyticsSystem.getStatistics();
                
                sender.sendMessage("§a=== §eAnalitik NeonDDoS §a===");
                sender.sendMessage("§7Total IP yang dipantau: §f" + analytics.get("totalTrackedIps"));
                sender.sendMessage("§7IP ancaman tinggi: §f" + analytics.get("highThreatIps"));
                sender.sendMessage("§7Total serangan tercatat: §f" + analytics.get("totalRecordedAttacks"));
                sender.sendMessage("§7Serangan 24 jam terakhir: §f" + analytics.get("attacksLast24Hours"));
                
                sender.sendMessage("§7§nStatistik 7 hari terakhir:");
                
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> dailyStats = (List<Map<String, Object>>) analytics.get("dailyStats");
                
                if (dailyStats != null && !dailyStats.isEmpty()) {
                    for (Map<String, Object> day : dailyStats) {
                        sender.sendMessage(String.format("§7%s: §f%d serangan, §f%d IP diblokir, §f%d false positives",
                            day.get("date"),
                            day.get("attacks"),
                            day.get("blockedIps"),
                            day.get("falsePositives")));
                    }
                } else {
                    sender.sendMessage("§7Belum ada data statistik harian yang tersedia");
                }
                
                return true;
            }
            
            if (args[0].equalsIgnoreCase("falsepositive")) {
                if (args.length < 2) {
                    sender.sendMessage("§cPenggunaan: /neonddos falsepositive <ip>");
                    return false;
                }
                
                String ip = args[1];
                analyticsSystem.markFalsePositive(ip);
                
                // Jika IP ada dalam daftar blokir, lepaskan
                if (firewallManager.unblockIpFromFirewall(ip)) {
                    sender.sendMessage("§aIP " + ip + " ditandai sebagai false positive dan dilepas dari blokir");
                } else {
                    sender.sendMessage("§aIP " + ip + " ditandai sebagai false positive");
                }
                
                return true;
            }
            
            if (args[0].equalsIgnoreCase("firewall")) {
                Map<String, Object> status = firewallManager.getFirewallStatus();
                
                sender.sendMessage("§a=== §eStatus Firewall NeonDDoS §a===");
                sender.sendMessage("§7Sistem Operasi: §f" + status.get("osType"));
                sender.sendMessage("§7Firewall dapat diakses: §f" + (boolean)status.get("accessible"));
                sender.sendMessage("§7Firewall diaktifkan: §f" + (boolean)status.get("enabled"));
                sender.sendMessage("§7Jumlah IP diblokir: §f" + status.get("blockedCount"));
                sender.sendMessage("§7Jumlah IP dalam whitelist: §f" + status.get("whitelistCount"));
                
                if ((boolean)status.get("accessible") && (boolean)status.get("enabled")) {
                    sender.sendMessage("§aFirewall sistem aktif dan berfungsi");
                } else if (!(boolean)status.get("enabled")) {
                    sender.sendMessage("§eFirewall sistem dinonaktifkan dalam konfigurasi");
                } else {
                    sender.sendMessage("§cFirewall sistem tidak dapat diakses");
                    sender.sendMessage("§cPastikan server berjalan dengan hak akses admin");
                }
                return true;
            }
            
            if (args[0].equalsIgnoreCase("whitelist")) {
                if (args.length < 2) {
                    sender.sendMessage("§cPenggunaan: /neonddos whitelist <add|remove|list> [ip]");
                    return false;
                }
                
                String action = args[1].toLowerCase();
                
                if (action.equals("list")) {
                    Set<String> whitelist = firewallManager.getWhitelistedIps();
                    sender.sendMessage("§a=== §eIP Whitelist §a===");
                    if (whitelist.isEmpty()) {
                        sender.sendMessage("§7Tidak ada IP dalam whitelist");
                    } else {
                        for (String whitelistedIp : whitelist) {
                            sender.sendMessage("§7 - " + whitelistedIp);
                        }
                    }
                    return true;
                }
                
                if (args.length < 3) {
                    sender.sendMessage("§cPenggunaan: /neonddos whitelist <add|remove> <ip>");
                    return false;
                }
                
                String ip = args[2];
                
                if (action.equals("add")) {
                    firewallManager.addToWhitelist(ip);
                    sender.sendMessage("§aIP " + ip + " ditambahkan ke whitelist");
                    return true;
                } else if (action.equals("remove")) {
                    firewallManager.removeFromWhitelist(ip);
                    sender.sendMessage("§aIP " + ip + " dihapus dari whitelist");
                    return true;
                }
            }
            
            if (args[0].equalsIgnoreCase("notify")) {
                if (args.length < 3) {
                    sender.sendMessage("§cPenggunaan: /neonddos notify <enable|disable> <ingame|discord|email|all>");
                    return false;
                }
                
                String action = args[1].toLowerCase();
                String channel = args[2].toLowerCase();
                boolean enable = action.equals("enable");
                
                if (channel.equals("ingame") || channel.equals("all")) {
                    notificationSystem.setEnableIngameNotifications(enable);
                    getConfig().set("notifications.ingame.enabled", enable);
                    sender.sendMessage("§7Notifikasi in-game " + (enable ? "§adiaktifkan" : "§cdinonaktifkan"));
                }
                
                if (channel.equals("discord") || channel.equals("all")) {
                    notificationSystem.setEnableDiscordWebhook(enable);
                    getConfig().set("notifications.discord.enabled", enable);
                    sender.sendMessage("§7Notifikasi Discord " + (enable ? "§adiaktifkan" : "§cdinonaktifkan"));
                }
                
                if (channel.equals("email") || channel.equals("all")) {
                    notificationSystem.setEnableEmailAlerts(enable);
                    getConfig().set("notifications.email.enabled", enable);
                    sender.sendMessage("§7Notifikasi Email " + (enable ? "§adiaktifkan" : "§cdinonaktifkan"));
                }
                
                saveConfig();
                notificationSystem.reloadConfiguration();
                return true;
            }
            
            if (args[0].equalsIgnoreCase("traffic")) {
                Map<String, Object> stats = trafficPrioritizer.getStatistics();
                
                sender.sendMessage("§a=== §eTraffic Prioritization §a===");
                sender.sendMessage("§7Status: " + (boolean)stats.get("enabled"));
                sender.sendMessage("§7Server load: §f" + stats.get("currentServerLoad") + "%");
                sender.sendMessage("§7IP yang dilacak: §f" + stats.get("trackingIpsCount"));
                sender.sendMessage("§7Player yang dikenal: §f" + stats.get("knownPlayersCount"));
                sender.sendMessage("§7Maks request/detik prioritas rendah: §f" + stats.get("maxLowPriorityRPS"));
                
                return true;
            }
            
            if (args[0].equalsIgnoreCase("settraffic")) {
                if (args.length < 3) {
                    sender.sendMessage("§cPenggunaan: /neonddos settraffic <enabled|bandwidth|maxrps> <value>");
                    return false;
                }
                
                String param = args[1].toLowerCase();
                String value = args[2].toLowerCase();
                
                if (param.equals("enabled")) {
                    boolean enabled = value.equals("true") || value.equals("yes") || value.equals("on");
                    trafficPrioritizer.setTrafficPrioritizationEnabled(enabled);
                    sender.sendMessage("§7Traffic prioritization " + (enabled ? "§adiaktifkan" : "§cdinonaktifkan"));
                    return true;
                } else if (param.equals("bandwidth")) {
                    boolean enabled = value.equals("true") || value.equals("yes") || value.equals("on");
                    trafficPrioritizer.setDynamicBandwidthAllocationEnabled(enabled);
                    sender.sendMessage("§7Dynamic bandwidth allocation " + (enabled ? "§adiaktifkan" : "§cdinonaktifkan"));
                    return true;
                } else if (param.equals("maxrps")) {
                    try {
                        int maxRps = Integer.parseInt(value);
                        trafficPrioritizer.setMaxLowPriorityRequestsPerSecond(maxRps);
                        sender.sendMessage("§7Max low priority RPS diatur ke §f" + maxRps);
                        return true;
                    } catch (NumberFormatException e) {
                        sender.sendMessage("§cNilai harus berupa angka");
                        return false;
                    }
                }
            }
            
            if (args[0].equalsIgnoreCase("ml")) {
                Map<String, Object> stats = mlEngine.getStatistics();
                
                sender.sendMessage("§a=== §eMachine Learning NeonDDoS §a===");
                sender.sendMessage("§7Status: " + (boolean)stats.get("enabled"));
                sender.sendMessage("§7Akurasi: §f" + String.format("%.2f%%", (double)stats.get("accuracy") * 100));
                sender.sendMessage("§7Precision: §f" + String.format("%.2f%%", (double)stats.get("precision") * 100));
                sender.sendMessage("§7Recall: §f" + String.format("%.2f%%", (double)stats.get("recall") * 100));
                sender.sendMessage("§7F1 Score: §f" + String.format("%.2f", (double)stats.get("f1Score")));
                sender.sendMessage("§7Current threshold: §f" + stats.get("currentThreshold"));
                
                // Tampilkan prediksi serangan
                MLEngine.AttackPrediction prediction = mlEngine.predictAttack();
                if (prediction.getProbability() > 0.3) {
                    sender.sendMessage("§e" + prediction.toString());
                } else {
                    sender.sendMessage("§7Tidak ada prediksi serangan dalam waktu dekat");
                }
                
                return true;
            }
            
            if (args[0].equalsIgnoreCase("mltrain")) {
                if (!sender.hasPermission("neonddos.admin")) {
                    sender.sendMessage("§cAnda tidak memiliki izin untuk menggunakan perintah ini");
                    return false;
                }
                
                sender.sendMessage("§7Memulai training model ML...");
                
                // Run training asynchronously
                new BukkitRunnable() {
                    @Override
                    public void run() {
                        mlEngine.trainModels();
                        
                        // Send completion message synchronously
                        new BukkitRunnable() {
                            @Override
                            public void run() {
                                sender.sendMessage("§aTraining model ML selesai");
                            }
                        }.runTask(neonddos.this); // Use neonddos.this to reference the outer plugin class
                    }
                }.runTaskAsynchronously(this);
                
                return true;
            }
            
            if (args[0].equalsIgnoreCase("toggleml")) {
                if (!sender.hasPermission("neonddos.admin")) {
                    sender.sendMessage("§cAnda tidak memiliki izin untuk menggunakan perintah ini");
                    return false;
                }
                
                Map<String, Object> stats = mlEngine.getStatistics();
                boolean currentState = (boolean)stats.get("enabled");
                mlEngine.setEnabled(!currentState);
                
                sender.sendMessage("§7Machine Learning " + 
                                  (!currentState ? "§adiaktifkan" : "§cdinonaktifkan"));
                return true;
            }
            
            if (args[0].equalsIgnoreCase("testdiscord")) {
                if (!sender.hasPermission("neonddos.admin")) {
                    sender.sendMessage("§cAnda tidak memiliki izin untuk menggunakan perintah ini");
                    return false;
                }
                
                sender.sendMessage("§7Mengirim notifikasi Discord test...");
                
                NotificationSystem notifSystem = getNotificationSystem();
                if (notifSystem != null) {
                    notifSystem.sendAttackNotification("127.0.0.1", 100, "TEST_ALERT");
                    sender.sendMessage("§aBerhasil mengirim request notifikasi Discord test");
                } else {
                    sender.sendMessage("§cNotification system belum diinisialisasi");
                }
                
                return true;
            }
        }
        return false;
    }
    
    /**
     * Mendapatkan instance ConnectionMonitor
     */
    public ConnectionMonitor getConnectionMonitor() {
        return connectionMonitor;
    }
    
    /**
     * Mendapatkan instance DdosDetector
     */
    public DdosDetector getDdosDetector() {
        return ddosDetector;
    }
    
    /**
     * Mendapatkan instance FirewallManager
     */
    public FirewallManager getFirewallManager() {
        return firewallManager;
    }
    
    /**
     * Mendapatkan instance NotificationSystem
     */
    public NotificationSystem getNotificationSystem() {
        return notificationSystem;
    }
    
    /**
     * Mendapatkan instance AnalyticsSystem
     */
    public AnalyticsSystem getAnalyticsSystem() {
        return analyticsSystem;
    }
    
    /**
     * Mendapatkan instance TrafficPrioritizer
     */
    public TrafficPrioritizer getTrafficPrioritizer() {
        return trafficPrioritizer;
    }
    
    /**
     * Mendapatkan instance TCPConnectionFilter
     */
    public TCPConnectionFilter getTcpConnectionFilter() {
        return tcpConnectionFilter;
    }
    
    /**
     * Mendapatkan instance GeoIPFilter
     */
    public GeoIPFilter getGeoIPFilter() {
        return geoIPFilter;
    }
    
    /**
     * Mendapatkan instance MLEngine
     */
    public MLEngine getMLEngine() {
        return mlEngine;
    }
}
