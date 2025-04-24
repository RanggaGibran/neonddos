package id.neonddos;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.scheduler.BukkitRunnable;

/**
 * Filter koneksi TCP canggih untuk mendeteksi dan memblokir SYN floods dan
 * serangan TCP lainnya
 */
public class TCPConnectionFilter {
    
    private final neonddos plugin;
    private final Logger logger;
    
    // Menyimpan data SYN handshakes per IP
    private final Map<String, SynTracker> synTrackers;
    
    // Konfigurasi
    private int maxSynPerSecond = 5;
    private int maxHalfOpenConnections = 20;
    private boolean enableSynCookies = true;
    
    public TCPConnectionFilter(neonddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.synTrackers = new ConcurrentHashMap<>();
        
        // Load konfigurasi
        loadConfiguration();
        
        // Mulai cleaning task
        startCleanupTask();
        
        logger.info("TCP Connection Filter diinisialisasi");
    }
    
    private void loadConfiguration() {
        FileConfiguration config = plugin.getConfig();
        
        maxSynPerSecond = config.getInt("tcp-filter.maxSynPerSecond", 5);
        maxHalfOpenConnections = config.getInt("tcp-filter.maxHalfOpenConnections", 20);
        enableSynCookies = config.getBoolean("tcp-filter.enableSynCookies", true);
    }
    
    private void startCleanupTask() {
        new BukkitRunnable() {
            @Override
            public void run() {
                synTrackers.entrySet().removeIf(entry -> 
                    System.currentTimeMillis() - entry.getValue().lastUpdated > 60000);
            }
        }.runTaskTimerAsynchronously(plugin, 20 * 60, 20 * 60);
    }
    
    /**
     * Proses koneksi TCP baru
     * @return true jika koneksi diterima, false jika ditolak
     */
    public boolean processNewConnection(InetAddress address, boolean isSyn, boolean isComplete) {
        String ip = address.getHostAddress();
        
        // Dapatkan atau buat tracker untuk IP ini
        SynTracker tracker = synTrackers.computeIfAbsent(ip, k -> new SynTracker());
        
        // Update tracker
        if (isSyn) {
            tracker.synCount++;
            tracker.lastUpdated = System.currentTimeMillis();
            
            // Cek SYN flood
            if (tracker.synCount > maxSynPerSecond) {
                logger.warning("Kemungkinan SYN flood dari " + ip + 
                              " (" + tracker.synCount + " SYNs dalam 1 detik)");
                
                // Notifikasi sistem
                if (plugin.getNotificationSystem() != null) {
                    plugin.getNotificationSystem().sendAttackNotification(
                        ip, 120, "SYN Flood");
                }
                
                // Rekam dalam analytics
                if (plugin.getAnalyticsSystem() != null) {
                    try {
                        plugin.getAnalyticsSystem().recordAttack(
                            address, "SYN Flood", 120);
                    } catch (Exception e) {
                        logger.warning("Error merekam serangan: " + e.getMessage());
                    }
                }
                
                // Blokir IP di firewall
                if (plugin.getFirewallManager() != null) {
                    plugin.getFirewallManager().blockIpInFirewall(ip);
                }
                
                return false;
            }
        }
        
        if (!isComplete) {
            tracker.halfOpenConnections++;
            
            // Cek half-open connection flood
            if (tracker.halfOpenConnections > maxHalfOpenConnections) {
                logger.warning("Terlalu banyak koneksi half-open dari " + ip);
                return false;
            }
        } else {
            // Koneksi selesai, kurangi half-open count
            if (tracker.halfOpenConnections > 0) {
                tracker.halfOpenConnections--;
            }
        }
        
        return true;
    }
    
    /**
     * Reset SYN counter setiap detik
     */
    public void resetCounters() {
        synTrackers.values().forEach(tracker -> {
            tracker.synCount = 0;
        });
    }
    
    /**
     * Kelas untuk melacak koneksi SYN per IP
     */
    private static class SynTracker {
        int synCount = 0;
        int halfOpenConnections = 0;
        long lastUpdated = System.currentTimeMillis();
    }
}